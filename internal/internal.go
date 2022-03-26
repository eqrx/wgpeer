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

	"eqrx.net/service"
	"eqrx.net/wgpeer/internal/peer"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"gopkg.in/yaml.v3"
)

const configPath = "/etc/wgpeer"

// Configuration is the unmarshalled form of the configuration file and contains all information
// of this node that are required for wgpeer.
type Configuration struct {
	// IfaceName if the wireguard interface we are managing.
	IfaceName string `yaml:"ifaceName"`
	// Peers is the set of peers this node wants to communicate with.
	Peers []peer.Peer `yaml:"peers"`
	// Resolver is the DNS resolver used for quering global endpoints.
	resolver peer.DNSResolver `yaml:"-"`
	// WGCtrl is the netlink client to configure wireguard interfaces.
	wgctrl *wgctrl.Client `yaml:"-"`
}

// Run performs configuration of the local wireguard instance according to
// the configuration file at configPath.
func (c *Configuration) Run(ctx context.Context, log logr.Logger, service *service.Service) error {
	control, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wg ctrl: %w", err)
	}

	c.resolver = &net.Resolver{PreferGo: true, StrictErrors: true, Dial: nil}
	c.wgctrl = control

	_ = service.MarkReady()
	defer func() { _ = service.MarkStopping() }()

	err = c.Loop(ctx, log)

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

// Run loads the wgpeer configuration from credentials and runs Run on it.
func Run(ctx context.Context, log logr.Logger, service *service.Service) error {
	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewBuffer(cfgBytes))

	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return fmt.Errorf("unmarshal config file: %w", err)
	}

	return configuration.Run(ctx, log, service)
}
