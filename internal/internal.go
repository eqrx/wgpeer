// Copyright (C) 2022 Alexander Sowitzki
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

// Package internal contains all the actual logic of the project.
package internal

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"

	"eqrx.net/wgpeer"
	"eqrx.net/wgpeer/internal/service"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"gopkg.in/yaml.v3"
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

	decoder := yaml.NewDecoder(bytes.NewBuffer(cfgBytes))

	var configuration wgpeer.Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return fmt.Errorf("unmarshal config file: %w", err)
	}

	control, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wg ctrl: %w", err)
	}

	service := service.New(
		&net.Resolver{PreferGo: true, StrictErrors: true, Dial: nil},
		configuration,
		control,
	)
	err = service.Loop(ctx, log)

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
