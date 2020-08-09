package piad

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.jonnrb.io/piad/link"
	"go.jonnrb.io/piad/session"
)

type Controller struct {
	LinkName  string
	RegionDNS string
	Username  string
	Password  string
}

func (c Controller) Run(ctx context.Context) error {
	s, err := c.start(ctx)
	if err != nil {
		return err
	}
	defer s.l.Close()

	return s.runAddKeyLoop(ctx)
}

func (c Controller) redact() Controller {
	if c.Username != "" {
		c.Username = "****"
	}
	if c.Password != "" {
		c.Password = "****"
	}
	return c
}

type controllerState struct {
	ctlr Controller
	l    link.Link
	pk   session.PublicKey
	srv  session.Server
	sn   session.Session

	isRefresh     bool
	lastHandshake time.Time
}

func (c Controller) start(ctx context.Context) (s controllerState, err error) {
	if c.RegionDNS == "" || c.Username == "" || c.Password == "" {
		err = fmt.Errorf("invalid controller: %+v", c.redact())
		return
	}
	if c.LinkName == "" {
		c.LinkName = "wg0"
	}
	s.ctlr = c

	s.srv, err = c.getServer(ctx)
	if err != nil {
		return
	}

	sk, err := session.NewKey()
	if err != nil {
		err = fmt.Errorf("could not generate session secret key: %w", err)
		return
	}
	s.pk = sk.PublicKey()

	s.l = link.Link(c.LinkName)

	err = s.l.Start(sk)
	if err != nil {
		err = fmt.Errorf("could not bring up interface %q: %w", c.LinkName, err)
	}
	return
}

func (s *controllerState) runAddKeyLoop(ctx context.Context) error {
	// Assume connecting is as good as a handshake since there isn't a great
	// timestamp to use until the first handshake.
	s.lastHandshake = time.Now()

	for {
		err := s.addKeyOnceAndSyncLoop(ctx)

		switch {
		case err == nil:
			continue
		case errors.Is(err, errNeedsReAdd):
			continue
		default:
			return err
		}
	}
}

func (s *controllerState) addKeyOnceAndSyncLoop(ctx context.Context) error {
	defer s.l.Stop()

	err := s.addKey(ctx)
	if err != nil {
		return fmt.Errorf(
			"error adding key to server in region %q: %w",
			s.ctlr.RegionDNS, err)
	}

	// After this, we're refreshing the key on errors.
	s.isRefresh = true

	return s.syncLoop(ctx)
}

func (s *controllerState) syncLoop(ctx context.Context) error {
	for {
		err := s.syncAndWatchOnce(ctx)
		if err != nil {
			return err
		}
	}
}

// Can be returned from deep within the bowels of the controller to trigger a
// re-add to PIA.
var errNeedsReAdd = errors.New("needs re-add")

func (s *controllerState) syncAndWatchOnce(ctx context.Context) error {
	did, err := s.l.Sync(s.sn)
	if err != nil {
		log.Printf("session failed to sync: %+v", s.sn)
		return fmt.Errorf("failed to sync dev %q: %w", string(s.l), err)
	}
	if did {
		log.Printf("synced device %q", string(s.l))
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(link.KeepaliveInterval):
		t, err := s.l.LastHandshake()
		now := time.Now()

		switch {
		case err == link.ErrNeedsSync:
			log.Printf("couldn't find last handshake time: %v", err)
			return nil
		case err == nil:
			s.lastHandshake = t
		}

		ago := now.Sub(s.lastHandshake)
		switch {
		case s.keepaliveIntervalsPastHandshakeInterval(10, now):
			return fmt.Errorf(
				"last handshake was %v ago; assuming the server is dead", ago)
		case s.keepaliveIntervalsPastHandshakeInterval(5, now):
			log.Printf("last handshake was %v ago; readding key to server", ago)
			return errNeedsReAdd
		case s.keepaliveIntervalsPastHandshakeInterval(2, now):
			log.Printf(
				"two keepalive intervals have passed since the last handshake (%v ago)",
				ago)
		}
	}
	return nil
}

func (s *controllerState) keepaliveIntervalsPastHandshakeInterval(n int, now time.Time) bool {
	const handshakeInterval = 120 * time.Second

	d := handshakeInterval + time.Duration(n)*link.KeepaliveInterval
	return s.lastHandshake.Add(d).Before(now)
}

func (c Controller) getServer(ctx context.Context) (s session.Server, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("error getting server for %q: %w", c.RegionDNS, err)
		}
	}()

	rm, err := session.GetServers(ctx)
	if err != nil {
		return
	}

	ss := rm[c.RegionDNS]
	if len(ss) == 0 {
		err = fmt.Errorf("no servers for region %q", c.RegionDNS)
		return
	}

	// Just grab the first one. We could do something more complex, but in
	// practice there's only ever one server.
	s = ss[0]
	return
}

func (s *controllerState) addKey(ctx context.Context) (err error) {
	N := 5
	prev := s.sn
	for i := 0; i < N; i++ {
		s.sn, err = s.srv.AddKey(ctx, s.ctlr.Username, s.ctlr.Password, s.pk)
		if err == nil {
			return
		}

		if s.isRefresh && errors.Is(err, session.StatusError(http.StatusConflict)) {
			// If we're only trying to refresh the key, a "conflict" error
			// implies the key already exists.
			log.Printf("adding key after dead connection; key exists")
			s.sn = prev
			return nil
		}

		backoff := (1 << i) * 25 * time.Millisecond
		log.Printf("got error %v; doing %v backoff %d/%d", err, backoff, i+1, N)

		select {
		case <-time.After(backoff):
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return
}
