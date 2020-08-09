package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"go.jonnrb.io/piad/api"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Session struct {
	Status     string    `json:"status"`
	ServerKey  PublicKey `json:"server_key"`
	ServerPort uint16    `json:"server_port"`
	ServerAddr net.UDPAddr
	ServerIP   net.IP `json:"server_ip"`
	ServerVIP  net.IP `json:"server_vip"`
	PeerIP     net.IP
	RawPeerIP  string    `json:"peer_ip"`
	PeerPubKey PublicKey `json:"peer_pubkey"`
	DNSServers []net.IP  `json:"dns_servers"`
}

func (s Server) AddKey(ctx context.Context, username, password string, key PublicKey) (sn Session, err error) {
	tok, err := api.GetToken(ctx, username, password)
	if err != nil {
		return
	}

	u := url.URL{
		Scheme: "https",
		Host:   s.Addr.String(),
		Path:   "addKey",
		RawQuery: url.Values{
			"pubkey": []string{wgtypes.Key(key).String()},
			"pt":     []string{string(tok)},
		}.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Host = s.CommonName

	cli := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				return tls.Dial(network, addr, &tls.Config{
					RootCAs:    certPool,
					ServerName: s.CommonName,
				})
			},
		},
	}

	res, err := cli.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = StatusError(res.StatusCode)
		return
	}

	err = json.NewDecoder(res.Body).Decode(&sn)
	sn.ServerAddr = net.UDPAddr{
		IP:   sn.ServerIP,
		Port: int(sn.ServerPort),
	}
	sn.PeerIP = net.ParseIP(strings.ReplaceAll(sn.RawPeerIP, "/32", ""))
	if err == nil && sn.Status != "OK" {
		err = fmt.Errorf("error from /addKey: %s", sn.Status)
	}
	return
}

type StatusError int

func (e StatusError) Error() string {
	return fmt.Sprintf("HTTP error %d", e)
}
