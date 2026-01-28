package model

type Site struct {
	Name         string `json:"name"`
	URLTemplate  string `json:"url_template"`
	Category     string `json:"category"`
	SuccessCodes []int  `json:"success_status"`
}

type Result struct {
	SiteName string `json:"site_name"`
	URL      string `json:"url"`
	Exists   bool   `json:"exists"`
	Status   int    `json:"status"`
}

type Task struct {
	Site     Site
	Username string
}
