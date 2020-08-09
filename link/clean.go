package link

import (
	"errors"
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
)

// Tears down routes and rules, but can be revived via l.Sync().
func (l Link) Stop() error {
	if err := flushRoutes(); err != nil {
		return fmt.Errorf("error flushing routes: %w", err)
	}
	if err := flushRules(); err != nil {
		return fmt.Errorf("error flushing rules: %w", err)
	}
	return nil
}

func (l Link) Close() error {
	if err := l.closeDev(); err != nil {
		return fmt.Errorf("error closing dev %q: %w", string(l), err)
	}
	return l.Stop()
}

func (l Link) closeDev() error {
	nl, err := netlink.LinkByName(string(l))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err == nil:
		return netlink.LinkDel(nl)
	default:
		return err
	}
}

func flushRoutes() error {
	rs, err := getOurRoutingTable()
	if err != nil {
		return err
	}
	for _, r := range rs {
		if err := netlink.RouteDel(&r); err != nil {
			return err
		}
	}
	return nil
}

func flushRules() error {
	allRules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("error getting routing rules: %w", err)
	}

	for _, r := range allRules {
		hasMark := r.Mark == FwMark
		hasOurTable := r.Table == FwMark
		hasInvert := r.Invert == true

		hasMainTable := r.Table == 254
		hasSuppressPrefixLen := r.SuppressPrefixlen == 0

		if (hasMark && hasOurTable && hasInvert) ||
			(hasMainTable && hasSuppressPrefixLen) {
			return netlink.RuleDel(&r)
		}
	}

	return nil
}
