package link

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"go.jonnrb.io/piad/session"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	KeepaliveInterval = 5 * time.Second
	FwMark            = 1337
)

func (l Link) Sync(s session.Session) (did bool, err error) {
	didDev, err := l.syncDev(s)
	if err != nil {
		err = fmt.Errorf("error syncing wg dev %q: %w", string(l), err)
		return
	}
	did = did || didDev

	didRoutingTables, err := l.syncRoutingTables(s)
	if err != nil {
		err = fmt.Errorf("error syncing routing tables: %w", err)
		return
	}
	did = did || didRoutingTables

	didRules, err := syncRules()
	if err != nil {
		err = fmt.Errorf("error syncing routing rules: %w", err)
		return
	}
	did = did || didRules

	return
}

func (l Link) syncDev(s session.Session) (did bool, err error) {
	cli, err := wgctrl.New()
	if err != nil {
		return
	}
	defer cli.Close()

	nl, err := netlink.LinkByName(string(l))
	if err != nil {
		err = fmt.Errorf(
			"couldn't get wg link %q (which should exist by now): %w",
			string(l), err)
		return
	}

	applyDev := func() (bool, error) {
		err := l.applyDev(cli, nl, s)
		return err == nil, err
	}

	dev, err := cli.Device(string(l))
	if err != nil {
		return
	}

	if dev.PublicKey != wgtypes.Key(s.PeerPubKey) {
		err = fmt.Errorf(
			"dev %q is configured with a different key than present in the session: %v != %v",
			l, dev.PublicKey, wgtypes.Key(s.PeerPubKey))
		return
	}

	if len(dev.Peers) != 1 {
		return applyDev()
	}

	p := dev.Peers[0]

	if !udpAddrEqual(p.Endpoint, &s.ServerAddr) {
		return applyDev()
	}

	if len(p.AllowedIPs) != 1 {
		return applyDev()
	}

	if ones, bits := p.AllowedIPs[0].Mask.Size(); bits != 32 && ones != 0 {
		return applyDev()
	}

	if p.PresharedKey != (wgtypes.Key{}) {
		return applyDev()
	}

	if p.PublicKey != wgtypes.Key(s.ServerKey) {
		return applyDev()
	}

	if p.PersistentKeepaliveInterval != KeepaliveInterval {
		return applyDev()
	}

	// From here on out, if the link state doesn't match, don't touch the wg
	// config.
	applyLinkState := func() (bool, error) {
		err := l.applyLinkState(nl, s)
		return err == nil, err
	}

	addrs, err := netlink.AddrList(nl, netlink.FAMILY_V4)
	if err != nil {
		err = fmt.Errorf("error listing addrs on %q: %w", string(l), err)
		return
	}

	if len(addrs) != 1 || !addrs[0].IP.Equal(s.PeerIP) {
		return applyLinkState()
	}

	if nl.Attrs().Flags&net.FlagUp == 0 {
		return applyLinkState()
	}

	return
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && a.Port == b.Port && a.Zone == b.Zone
}

func (l Link) applyDev(cli *wgctrl.Client, nl netlink.Link, s session.Session) error {
	keepaliveInterval := KeepaliveInterval
	fwMark := FwMark

	err := cli.ConfigureDevice(string(l), wgtypes.Config{
		FirewallMark: &fwMark,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   wgtypes.Key(s.ServerKey),
			Endpoint:                    &s.ServerAddr,
			PersistentKeepaliveInterval: &keepaliveInterval,
			ReplaceAllowedIPs:           true,
			AllowedIPs: []net.IPNet{{
				IP:   net.ParseIP("0.0.0.0"),
				Mask: net.CIDRMask(0, 32),
			}},
		}},
	})
	if err != nil {
		return fmt.Errorf(
			"failed to configure wg device %q: %w", string(l), err)
	}

	return l.applyLinkState(nl, s)
}

func (l Link) applyLinkState(nl netlink.Link, s session.Session) error {
	err := netlink.LinkSetUp(nl)
	if err != nil {
		return fmt.Errorf("couldn't set wg link %q up: %w", string(l), err)
	}

	addrs, err := netlink.AddrList(nl, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("error listing addrs on %q: %w", string(l), err)
	}

	var hasAddr bool
	for _, addr := range addrs {
		if addr.IP.Equal(s.PeerIP) {
			hasAddr = true
		} else {
			err := netlink.AddrDel(nl, &addr)
			if err != nil {
				return fmt.Errorf(
					"error removing superfluous address %v from dev %q: %w",
					addr, string(l), err)
			}
		}
	}

	if hasAddr {
		return nil
	}

	addr := netlink.Addr{
		IPNet: &net.IPNet{
			IP:   s.PeerIP,
			Mask: net.CIDRMask(32, 32),
		},
	}

	err = netlink.AddrAdd(nl, &addr)
	if err != nil {
		return fmt.Errorf(
			"could not add address %v to dev %q: %w", addr, string(l), err)
	}

	return nil
}

func (l Link) syncRoutingTables(s session.Session) (did bool, err error) {
	rs, err := getOurRoutingTable()
	if err != nil {
		err = fmt.Errorf("could not get routing tables: %w", err)
		return
	}

	var (
		existingGatewayStaticRoute *netlink.Route
		existingDefaultRoute       *netlink.Route
		unknownRoutes              []netlink.Route
	)
	for _, r := range rs {
		if r.Dst == nil {
			existingDefaultRoute = &netlink.Route{}
			*existingDefaultRoute = r
			continue
		}
		ones, bits := r.Dst.Mask.Size()
		if bits == 32 && ones == 32 && r.Dst.IP.Equal(s.ServerVIP) {
			existingGatewayStaticRoute = &netlink.Route{}
			*existingGatewayStaticRoute = r
			continue
		}
		unknownRoutes = append(unknownRoutes, r)
	}

	didGatewayStatic, err := l.syncGatewayStaticRoute(s, existingGatewayStaticRoute)
	if err != nil {
		err = fmt.Errorf(
			"could not add static route to %s: %w", s.ServerVIP, err)
		return
	}
	did = did || didGatewayStatic

	didDefault, err := syncDefaultRoute(s, existingDefaultRoute)
	if err != nil {
		err = fmt.Errorf("could not add default route: %w", err)
		return
	}
	did = did || didDefault

	didPrune, err := pruneUnknownRoutes(unknownRoutes)
	if err != nil {
		err = fmt.Errorf("could not prune unknown routes: %w", err)
		return
	}
	did = did || didPrune

	return
}

func (l Link) syncGatewayStaticRoute(s session.Session, oldGatewayStaticRoute *netlink.Route) (did bool, err error) {
	if oldGatewayStaticRoute != nil {
		return
	}

	nl, err := netlink.LinkByName(string(l))
	if err != nil {
		return
	}

	gatewayStaticRoute := netlink.Route{
		LinkIndex: nl.Attrs().Index,
		Dst: &net.IPNet{
			IP:   s.ServerVIP,
			Mask: net.CIDRMask(32, 32),
		},
		Table: FwMark,
		Scope: netlink.SCOPE_LINK,
	}

	err = netlink.RouteAdd(&gatewayStaticRoute)
	did = true
	return
}

func syncDefaultRoute(s session.Session, oldDefaultRoute *netlink.Route) (did bool, err error) {
	if oldDefaultRoute != nil && oldDefaultRoute.Gw.Equal(s.ServerVIP) {
		return
	}

	defaultRoute := netlink.Route{
		Gw: s.ServerVIP,
		Dst: &net.IPNet{
			IP:   net.ParseIP("0.0.0.0"),
			Mask: net.CIDRMask(32, 0),
		},
		Table: FwMark,
	}

	if oldDefaultRoute != nil {
		err = netlink.RouteReplace(&defaultRoute)
	} else {
		err = netlink.RouteAdd(&defaultRoute)
	}
	did = true
	return
}

func pruneUnknownRoutes(unknownRoutes []netlink.Route) (did bool, err error) {
	if len(unknownRoutes) == 0 {
		return
	}

	did = true
	for _, r := range unknownRoutes {
		err = netlink.RouteDel(&r)
		if err != nil {
			return
		}
	}
	return
}

func getOurRoutingTable() ([]netlink.Route, error) {
	// The fw mark is also our routing table. Clever eh?
	f := netlink.Route{Table: FwMark}
	return netlink.RouteListFiltered(netlink.FAMILY_V4, &f, netlink.RT_FILTER_TABLE)
}

func syncRules() (did bool, err error) {
	allRules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		err = fmt.Errorf("error getting routing rules: %w", err)
		return
	}

	didBlackholeRule, err := syncBlackholeRule(allRules)
	if err != nil {
		err = fmt.Errorf("error syncing blackhole rule: %w", err)
		return
	}
	did = did || didBlackholeRule

	didLocalExemption, err := syncLocalExemption(allRules)
	if err != nil {
		err = fmt.Errorf("error syncing local exemption rule: %w", err)
		return
	}
	did = did || didLocalExemption

	return
}

func syncBlackholeRule(allRules []netlink.Rule) (did bool, err error) {
	for _, r := range allRules {
		hasMark := r.Mark == FwMark
		hasTable := r.Table == FwMark
		hasInvert := r.Invert == true

		switch {
		case hasMark && hasTable && hasInvert:
			return
		case hasMark || hasTable:
			err = netlink.RuleDel(&r)
			if err != nil {
				err = fmt.Errorf("error deleting rule %+v: %w", r, err)
				return
			}
		}
	}

	did = true
	r := netlink.Rule{
		Mark:   FwMark,
		Table:  FwMark,
		Invert: true,

		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Mask:              -1,
		Goto:              -1,
		Flow:              -1,
	}
	err = netlink.RuleAdd(&r)
	if err != nil {
		err = fmt.Errorf("error adding blackhole rule %+v: %w", r, err)
	}
	return
}

func syncLocalExemption(allRules []netlink.Rule) (did bool, err error) {
	const mainTable = 254

	for _, r := range allRules {
		hasTable := r.Table == mainTable
		hasSuppressPrefixLen := r.SuppressPrefixlen == 0

		if hasTable && hasSuppressPrefixLen {
			return
		}
	}

	did = true
	r := netlink.Rule{
		Table:             mainTable,
		SuppressPrefixlen: 0,

		SuppressIfgroup: -1,
		Priority:        -1,
		Mark:            -1,
		Mask:            -1,
		Goto:            -1,
		Flow:            -1,
	}
	err = netlink.RuleAdd(&r)
	return
}
