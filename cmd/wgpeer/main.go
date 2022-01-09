package main

import (
	"context"
	stdlog "log"
	"os"
	"os/signal"

	"dev.eqrx.net/wgpeer/internal"
	"github.com/go-logr/stdr"
	"golang.org/x/sys/unix"
)

func main() {
	log := stdr.New(stdlog.New(os.Stderr, "", 0))

	var err error
	defer func() {
		if err != nil {
			log.Error(err, "program error")
			os.Exit(1)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGTERM, unix.SIGINT)
	defer cancel()

	err = internal.Run(ctx, log)
}
