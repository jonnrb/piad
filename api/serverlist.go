package api

import (
	"context"
	"encoding/json"
	"net/http"
)

const ServerListEndpoint = "https://serverlist.piaservers.net/vpninfo/servers/new"

type ServerList struct {
	Groups  map[string][]Group `json:"groups"`
	Regions []Region           `json:"regions"`
}

type Group struct {
	Name  string   `json:"name"`
	Ports []uint16 `json:"ports"`
}

type Region struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Country     string              `json:"country"`
	AutoRegion  bool                `json:"auto_region"`
	DNS         string              `json:"dns"`
	PortForward bool                `json:"port_forward"`
	Geo         bool                `json:"geo"`
	Servers     map[string][]Server `json:"servers"`
}

type Server struct {
	IP         string `json:"ip"`
	CommonName string `json:"cn"`
}

func GetServerList(ctx context.Context) (l ServerList, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", ServerListEndpoint, nil)
	if err != nil {
		return
	}

	res, err := (&http.Client{}).Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&l)
	return
}
