// Package internal contains all the actual logic of the project.
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"dev.eqrx.net/wgpeer"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const configPath = "/etc/wgpeer"

// Run performs configuration of the local wireguard instance according to
// the configuration file at configPath.
//
// This is done by unmarshalling the configuration file, opening a wireguard
// control interface and call loop from the link struct of the internal package.
func Run(ctx context.Context, log logr.Logger) error {
	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewBuffer(cfgBytes))
	decoder.DisallowUnknownFields()

	var configuration wgpeer.Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return fmt.Errorf("unmarshal config file: %w", err)
	}

	control, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wg ctrl: %w", err)
	}

	link := link{&net.Resolver{PreferGo: true, StrictErrors: true, Dial: nil}, configuration, control}
	err = link.loop(ctx, log)

	cErr := control.Close()

	switch {
	case err != nil && cErr != nil:
		return fmt.Errorf("run loop: %w. Also close wg ctrl: %v", err, cErr)
	case err != nil:
		return fmt.Errorf("run loop: %w", err)
	case cErr != nil:
		return fmt.Errorf("close wg ctrl: %w", cErr)
	default:
		return nil
	}
}
