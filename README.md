# 🐬 echolocate

**echolocate** is a high‑performance CLI OSINT tool for checking username availability across popular sites. It’s fast, concurrent, and built for clean terminal UX with a live progress TUI.

---

<p align="center" > <img src=https://github.com/user-attachments/assets/d7abcd28-963d-4f6c-98c8-36aea8e74b11/> </p>

---

## ✨ Highlights

- **Producer → Worker → Aggregator** pipeline for high concurrency
- **20 workers by default** (configurable)
- **5s strict timeout** per request (configurable)
- **Live TUI progress bar** with tasteful colors (dark/light adaptive)
- **Soft‑fail policy** for timeouts / 5xx responses
- **JSON or CSV export**
- **SOCKS5 proxy** support for stealth

---

## 🚀 Quick Start

```bash
# build
make build 2>/dev/null || go build -o echolocate

# run a scan
echolocate scan <username>
```

Example:
```bash
echolocate scan test12
```

---

## 📦 Install

```bash
go install ./...
```

Or build a local binary:
```bash
go build -o echolocate
```

---

## 🧭 Usage

```bash
echolocate scan <username> [flags]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --timeout` | Request timeout in seconds | `5` |
| `-w, --workers` | Number of concurrent workers | `20` |
| `-o, --output` | Export results to JSON or CSV | *(none)* |
| `--proxy` | SOCKS5 proxy (e.g. `socks5://127.0.0.1:9050`) | *(none)* |

---

## ✅ Output

Results are shown as **Taken / Available / Unknown**.

- **Taken**: a matching success status code (typically 200)
- **Available**: site responds but doesn’t match success criteria
- **Unknown**: timeout, 5xx, or blocked/rate‑limited responses (401/403/429)

You can export the full result set:

```bash
echolocate scan test12 -o results.json
echolocate scan test12 -o results.csv
```

---

## 🗂 Registry

The site registry is a JSON file with name, URL template, and success criteria.

Location:
```
internal/registry/sites.json
```

Each site supports a **custom color** for display in the results table:

```json
{
  "name": "GitHub",
  "url_template": "https://github.com/{username}",
  "category": "dev",
  "color": "#60A5FA",
  "success_status": [200],
  "not_found_status": [404]
}
```

**Notes:**
- Use `{username}` (or `{u}`) as the placeholder in `url_template`.
- If a site repeatedly shows **Unknown**, it’s often blocking bot traffic. Consider replacing it.
- Optional fields:
  - `not_found_status`: status codes that indicate the username is available.
  - `not_found_regex`: regex patterns that detect "not found" pages when the status is 200.
  - `request_method`: set to `"GET"` when `HEAD` is unreliable.

---

## 🧩 Architecture

```
Registry → Dispatcher → Worker Pool → Aggregator → TUI + Results
```

- Registry is embedded at build time
- Dispatcher feeds a buffered task channel
- Workers share a pooled `http.Client`
- Aggregator updates the TUI and collects hits

---

## 🔐 Proxy (SOCKS5)

```bash
echolocate scan test12 --proxy socks5://127.0.0.1:9050
```

---

## 🛠 Development

```bash
# tidy dependencies
go mod tidy

# build
go build ./...
```

---

## ⚠️ Disclaimer

This tool is for **legitimate OSINT and research**. Always respect target sites’ terms of service, robots rules, and rate limits.

---

## 📄 License

MIT
