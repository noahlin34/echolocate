package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"echolocate/internal/model"
	"echolocate/internal/registry"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

const defaultWorkers = 20
const defaultTimeout = 5 * time.Second
const maxBodyBytes = 64 * 1024

var (
	flagTimeout int
	flagWorkers int
	flagOutput  string
	flagProxy   string
)

func init() {
	scanCmd.Flags().IntVarP(&flagTimeout, "timeout", "t", int(defaultTimeout.Seconds()), "Request timeout in seconds")
	scanCmd.Flags().IntVarP(&flagWorkers, "workers", "w", defaultWorkers, "Number of concurrent workers")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Export results to JSON or CSV")
	scanCmd.Flags().StringVar(&flagProxy, "proxy", "", "Optional SOCKS5 proxy (e.g., socks5://127.0.0.1:9050)")

	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan <username>",
	Short: "Scan for a username across known sites",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

type progressMsg struct {
	current int
}

type doneMsg struct{}
type quitMsg struct{}

type progressModel struct {
	total    int
	current  int
	bar      progress.Model
	ready    chan struct{}
	username string
}

func newProgressModel(total int, ready chan struct{}, username string) progressModel {
	bar := progress.New(
		progress.WithGradient("#60A5FA", "#FBBF24"),
		progress.WithWidth(40),
		progress.WithoutPercentage(),
	)
	return progressModel{
		total:    total,
		bar:      bar,
		ready:    ready,
		username: username,
	}
}

func (m progressModel) Init() tea.Cmd {
	return func() tea.Msg {
		close(m.ready)
		return nil
	}
}

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case progressMsg:
		m.current = msg.current
		percent := float64(m.current) / float64(m.total)
		if percent > 1 {
			percent = 1
		}
		return m, m.bar.SetPercent(percent)
	case doneMsg:
		m.current = m.total
		return m, tea.Batch(
			m.bar.SetPercent(1),
			tea.Tick(80*time.Millisecond, func(time.Time) tea.Msg {
				return quitMsg{}
			}),
		)
	case quitMsg:
		return m, tea.Quit
	}
	var cmd tea.Cmd
	updated, cmd := m.bar.Update(msg)
	if model, ok := updated.(progress.Model); ok {
		m.bar = model
	}
	return m, cmd
}

func (m progressModel) View() string {
	if m.total == 0 {
		return "No sites loaded."
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#E2E8F0"}).Render("echolocate")
	tagline := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#475569", Dark: "#94A3B8"}).Render("quietly mapping the social web")
	stats := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#94A3B8"}).Render(fmt.Sprintf("%d/%d", m.current, m.total))
	target := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#0EA5E9", Dark: "#60A5FA"}).Render(m.username)
	line := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#334155", Dark: "#CBD5F5"}).Render("Scanning profiles for")

	header := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#E5E7EB", Dark: "#334155"}).
		Padding(0, 1).
		Render(fmt.Sprintf("%s  %s\n%s\n%s %s", title, stats, tagline, line, target))

	barView := m.bar.View()
	if m.current >= m.total {
		barView = m.bar.ViewAs(1)
	}

	barLine := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#E5E7EB", Dark: "#334155"}).
		Padding(0, 1).
		Render(barView)

	return fmt.Sprintf("%s\n%s\n", header, barLine)
}

func runScan(cmd *cobra.Command, args []string) error {
	username := args[0]

	sites, err := registry.Load()
	if err != nil {
		return err
	}
	if len(sites) == 0 {
		return errors.New("registry is empty")
	}

	if flagWorkers <= 0 {
		flagWorkers = defaultWorkers
	}
	if flagTimeout <= 0 {
		flagTimeout = int(defaultTimeout.Seconds())
	}

	timeout := time.Duration(flagTimeout) * time.Second
	client, err := buildClient(timeout, flagProxy)
	if err != nil {
		return err
	}

	tasks := make(chan model.Task, len(sites))
	results := make(chan model.Result, len(sites))

	var wg sync.WaitGroup
	for i := 0; i < flagWorkers; i++ {
		wg.Add(1)
		go worker(client, tasks, results, &wg, timeout)
	}

	var prog *tea.Program
	var progErr chan error
	useTUI := term.IsTerminal(int(os.Stdout.Fd()))
	if useTUI {
		ready := make(chan struct{})
		prog = tea.NewProgram(newProgressModel(len(sites), ready, username))
		progErr = make(chan error, 1)
		go func() {
			_, err := prog.Run()
			progErr <- err
		}()
		<-ready
	}

	aggDone := make(chan aggResult, 1)
	go aggregator(results, prog, aggDone)

	go func() {
		for _, site := range sites {
			tasks <- model.Task{Site: site, Username: username}
		}
		close(tasks)
		wg.Wait()
		close(results)
	}()

	agg := <-aggDone
	if useTUI && prog != nil {
		prog.Send(progressMsg{current: len(sites)})
		prog.Send(doneMsg{})
		if err := <-progErr; err != nil {
			return err
		}
	}

	fmt.Println(renderResults(agg.Results))

	if flagOutput != "" {
		if err := writeOutput(flagOutput, agg.Results); err != nil {
			return err
		}
		fmt.Printf("Results exported to %s\n", flagOutput)
	}

	return nil
}

type aggResult struct {
	Results []model.Result
	Hits    []model.Result
}

func aggregator(results <-chan model.Result, prog *tea.Program, done chan<- aggResult) {
	collected := make([]model.Result, 0, cap(results))
	hits := make([]model.Result, 0)
	count := 0

	for res := range results {
		collected = append(collected, res)
		if res.Exists {
			hits = append(hits, res)
		}
		count++
		if prog != nil {
			prog.Send(progressMsg{current: count})
		}
	}

	done <- aggResult{Results: collected, Hits: hits}
}

func worker(client *http.Client, tasks <-chan model.Task, results chan<- model.Result, wg *sync.WaitGroup, timeout time.Duration) {
	defer wg.Done()

	for task := range tasks {
		results <- checkSite(client, task.Site, task.Username, timeout)
	}
}

func checkSite(client *http.Client, site model.Site, username string, timeout time.Duration) model.Result {
	urlStr := strings.ReplaceAll(site.URLTemplate, "{u}", username)
	urlStr = strings.ReplaceAll(urlStr, "{username}", username)

	method := http.MethodHead
	if strings.EqualFold(site.RequestMethod, http.MethodGet) {
		method = http.MethodGet
	}

	status, body, err := doRequest(client, method, urlStr, timeout, method == http.MethodGet && len(site.NotFoundRegex) > 0)
	if err != nil {
		log.Printf("%s: %v", site.Name, err)
		return model.Result{SiteName: site.Name, URL: urlStr, Exists: false, Status: 0, Color: site.Color}
	}

	if status >= 500 {
		log.Printf("%s: upstream error %d", site.Name, status)
		return model.Result{SiteName: site.Name, URL: urlStr, Exists: false, Status: status, Color: site.Color}
	}

	if method == http.MethodHead && len(site.NotFoundRegex) > 0 {
		status, body, err = doRequest(client, http.MethodGet, urlStr, timeout, true)
		if err != nil {
			log.Printf("%s: %v", site.Name, err)
			return model.Result{SiteName: site.Name, URL: urlStr, Exists: false, Status: 0, Color: site.Color}
		}
		if status >= 500 {
			log.Printf("%s: upstream error %d", site.Name, status)
			return model.Result{SiteName: site.Name, URL: urlStr, Exists: false, Status: status, Color: site.Color}
		}
	}

	successCodes := site.SuccessCodes
	if len(successCodes) == 0 {
		successCodes = []int{http.StatusOK}
	}

	exists := statusIn(successCodes, status)

	if statusIn(site.NotFoundCodes, status) || matchesNotFound(body, site.NotFoundRegex) {
		exists = false
	}

	return model.Result{SiteName: site.Name, URL: urlStr, Exists: exists, Status: status, Color: site.Color}
}

func doRequest(client *http.Client, method, urlStr string, timeout time.Duration, readBody bool) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return 0, "", err
	}
	addHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		if isTimeout(err) {
			return 0, "", fmt.Errorf("timeout")
		}
		return 0, "", err
	}
	defer resp.Body.Close()

	if method == http.MethodHead && resp.StatusCode == http.StatusMethodNotAllowed {
		return doRequest(client, http.MethodGet, urlStr, timeout, readBody)
	}

	body := ""
	if readBody {
		limited := io.LimitReader(resp.Body, maxBodyBytes)
		if data, readErr := io.ReadAll(limited); readErr == nil {
			body = string(data)
		}
	}

	return resp.StatusCode, body, nil
}

func statusIn(codes []int, status int) bool {
	for _, code := range codes {
		if status == code {
			return true
		}
	}
	return false
}

func matchesNotFound(body string, patterns []string) bool {
	if body == "" || len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Printf("invalid not_found_regex %q: %v", pattern, err)
			continue
		}
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

func addHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "echolocate/0.1")
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func buildClient(timeout time.Duration, proxyAddr string) (*http.Client, error) {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if proxyAddr != "" {
		dialer, err := socks5Dialer(proxyAddr)
		if err != nil {
			return nil, err
		}
		transport.Proxy = nil
		transport.DialContext = dialer.DialContext
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	return client, nil
}

type contextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

func socks5Dialer(addr string) (contextDialer, error) {
	if !strings.Contains(addr, "://") {
		addr = "socks5://" + addr
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s", parsed.Scheme)
	}

	dialer, err := proxy.SOCKS5("tcp", parsed.Host, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := dialer.(contextDialer)
	if !ok {
		return nil, errors.New("proxy dialer does not support context")
	}
	return ctxDialer, nil
}

func renderResults(results []model.Result) string {
	if len(results) == 0 {
		return "No results."
	}

	headStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#0EA5E9", Dark: "#7DD3FC"})
	cellStyle := lipgloss.NewStyle()
	takenStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#F87171"})
	availStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#16A34A", Dark: "#4ADE80"})
	unknownStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#9CA3AF", Dark: "#CBD5F5"})

	headers := []string{"Site", "URL", "Status"}
	rows := make([][]string, 0, len(results))
	for _, res := range results {
		siteStyle := cellStyle
		if res.Color != "" {
			siteStyle = siteStyle.Foreground(lipgloss.Color(res.Color))
		}
		siteName := siteStyle.Render(res.SiteName)
		rows = append(rows, []string{siteName, res.URL, statusLabel(res, takenStyle, availStyle, unknownStyle)})
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, row := range rows {
		for i, col := range row {
			if lipgloss.Width(col) > widths[i] {
				widths[i] = lipgloss.Width(col)
			}
		}
	}

	var (
		takenCount   int
		availCount   int
		unknownCount int
		unknownSites []string
	)

	for _, res := range results {
		if isUnknownStatus(res.Status) {
			unknownCount++
			unknownSites = append(unknownSites, res.SiteName)
			continue
		}
		if res.Exists {
			takenCount++
		} else {
			availCount++
		}
	}

	var b strings.Builder
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#E2E8F0"}).Render("Results")
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(formatRow(headers, widths, headStyle))
	b.WriteString("\n")
	for _, row := range rows {
		b.WriteString(formatRow(row, widths, cellStyle))
		b.WriteString("\n")
	}
	summary := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#94A3B8"}).Render(
		fmt.Sprintf("Taken: %d  Available: %d  Unknown: %d", takenCount, availCount, unknownCount),
	)
	b.WriteString(summary)
	b.WriteString("\n")
	if len(unknownSites) > 0 {
		notice := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#F59E0B", Dark: "#FBBF24"}).Render(
			"Unknown/blocked sites to consider replacing: " + strings.Join(unknownSites, ", "),
		)
		b.WriteString(notice)
		b.WriteString("\n")
	}

	return b.String()
}

func formatRow(cols []string, widths []int, style lipgloss.Style) string {
	cells := make([]string, len(cols))
	for i, col := range cols {
		cells[i] = style.Render(padRight(col, widths[i]))
	}
	return strings.Join(cells, "  ")
}

func padRight(s string, width int) string {
	if lipgloss.Width(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-lipgloss.Width(s))
}

func isUnknownStatus(status int) bool {
	if status == 0 || status >= 500 {
		return true
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func statusLabel(res model.Result, takenStyle, availStyle, unknownStyle lipgloss.Style) string {
	if isUnknownStatus(res.Status) {
		return unknownStyle.Render("Unknown")
	}
	if res.Exists {
		return takenStyle.Render("Taken")
	}
	return availStyle.Render("Available")
}

func writeOutput(path string, results []model.Result) error {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".csv" {
		return writeCSV(path, results)
	}
	return writeJSON(path, results)
}

func writeJSON(path string, results []model.Result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func writeCSV(path string, results []model.Result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	if err := w.Write([]string{"site_name", "url", "exists", "status"}); err != nil {
		return err
	}
	for _, res := range results {
		row := []string{res.SiteName, res.URL, fmt.Sprintf("%t", res.Exists), fmt.Sprintf("%d", res.Status)}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
