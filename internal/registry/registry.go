package registry

import (
	_ "embed"
	"encoding/json"

	"echolocate/internal/model"
)

//go:embed sites.json
var sitesData []byte

func Load() ([]model.Site, error) {
	var sites []model.Site
	if err := json.Unmarshal(sitesData, &sites); err != nil {
		return nil, err
	}
	return sites, nil
}
