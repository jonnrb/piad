package link

import (
	"errors"
	"os"

	"github.com/vishvananda/netlink"
	"go.jonnrb.io/piad/session"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Link string

func (l Link) Start(sk session.SecretKey) error {
	err := netlink.LinkAdd(l.toNetlinkLink())
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}

	return l.setKey(sk)
}

func (l Link) toNetlinkLink() *netlink.Wireguard {
	return &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: string(l),
		},
	}
}

func (l Link) setKey(sk session.SecretKey) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()

	wk := wgtypes.Key(sk)
	return c.ConfigureDevice(string(l), wgtypes.Config{PrivateKey: &wk})
}
