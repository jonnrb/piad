package link

import (
	"errors"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

var ErrNeedsSync = errors.New("device needs sync")

func (l Link) LastHandshake() (t time.Time, err error) {
	cli, err := wgctrl.New()
	if err != nil {
		return
	}
	defer cli.Close()

	dev, err := cli.Device(string(l))
	if err != nil {
		return
	}

	if len(dev.Peers) != 1 {
		err = ErrNeedsSync
		return
	}

	t = dev.Peers[0].LastHandshakeTime
	return
}
