package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"go.jonnrb.io/piad"
)

func main() {
	c := piad.Controller{}
	var d time.Duration

	flag.StringVar(&c.LinkName, "linkName", "", "Name to give Wireguard link")
	flag.StringVar(&c.Username, "username", "", "PIA username")
	flag.StringVar(&c.Password, "password", "", "PIA password")
	flag.StringVar(&c.RegionDNS, "server", "",
		"DNS of server region (e.g. us-newyorkcity.privacy.network)")
	flag.DurationVar(&d, "duration", 0,
		"How long to run the VPN for (this is for debugging)")

	flag.Parse()

	ctx, cancel := getCtx(d)
	defer cancel()

	err := c.Run(ctx)
	if err != nil {
		log.Printf("controller exited with err: %v", err)
	}
}

func getCtx(d time.Duration) (context.Context, func()) {
	ctx, cancel := newCtx(d)

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		defer signal.Stop(c)
		select {
		case <-ctx.Done():
		case <-c:
			cancel()
		}
	}()

	return ctx, cancel
}

func newCtx(d time.Duration) (context.Context, func()) {
	if d == 0 {
		return context.WithCancel(context.Background())
	} else {
		return context.WithTimeout(context.Background(), d)
	}
}
