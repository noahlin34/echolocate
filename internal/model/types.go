package model

type Site struct {
	Name         string `json:"name"`
	URLTemplate  string `json:"url_template"`
	Category     string `json:"category"`
	Color        string `json:"color"`
	SuccessCodes []int  `json:"success_status"`
}

type Result struct {
	SiteName string `json:"site_name"`
	URL      string `json:"url"`
	Exists   bool   `json:"exists"`
	Status   int    `json:"status"`
	Color    string `json:"color,omitempty"`
}

type Task struct {
	Site     Site
	Username string
}
