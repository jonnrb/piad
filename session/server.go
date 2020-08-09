package session

import (
	"context"
	"errors"
	"fmt"
	"net"

	"go.jonnrb.io/piad/api"
)

type ServerList map[string][]Server

type Server struct {
	Addr       net.TCPAddr
	CommonName string
}

func GetServers(ctx context.Context) (ServerList, error) {
	ul, err := api.GetServerList(ctx)
	if err != nil {
		return nil, err
	}

	gs, ok := ul.Groups["wg"]
	if !ok || len(gs) == 0 {
		return nil, errors.New("no wireguard port groups")
	}

	var wgp uint16
	for _, g := range gs {
		if g.Name != "wireguard" {
			continue
		}
		for _, p := range g.Ports {
			wgp = p
			break
		}
		break
	}
	if wgp == 0 {
		return nil, errors.New("no wireguard port in port groups")
	}

	dl := make(ServerList)
	for _, r := range ul.Regions {
		us, ok := r.Servers["wg"]
		if !ok || len(us) == 0 {
			continue
		}
		if _, ok := dl[r.DNS]; ok {
			return nil, fmt.Errorf("duplicate region DNS: %v", r.DNS)
		}
		ds := make([]Server, len(us))
		for i, u := range us {
			ds[i] = Server{
				Addr: net.TCPAddr{
					IP:   net.ParseIP(u.IP),
					Port: int(wgp),
				},
				CommonName: u.CommonName,
			}
		}
		dl[r.DNS] = ds
	}
	return dl, nil
}
