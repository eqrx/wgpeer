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

// Package service bundles all the other packages.
package service

import (
	"context"
	"fmt"
	"time"

	"eqrx.net/wgpeer"
	"eqrx.net/wgpeer/internal/netlink"
	"eqrx.net/wgpeer/internal/peer"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGController allows quering and configuration WG devices.
type WGController interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
}

// Service is a helper struct that bundles all the common handles.
type Service struct {
	// Resolver is the DNS resolver used for quering global endpoints.
	resolver peer.DNSResolver
	// Conf contains the configuration of this node.
	conf wgpeer.Configuration
	// WGCtrl is the netlink client to configure wireguard interfaces.
	wgctrl WGController
}

// New creates a new service instance with the given handles.
func New(resolver peer.DNSResolver, conf wgpeer.Configuration, wgctrl WGController) *Service {
	return &Service{resolver, conf, wgctrl}
}

// Loop updates the wireguard configuration until the given ctx is cancelled.
func (s *Service) Loop(ctx context.Context, log logr.Logger) error {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			err := s.refresh(ctx, log)
			if err != nil {
				return err
			}

			timer.Reset(peer.HandshakeTimeout)
		}
	}
}

// refresh queries the current state of the managed wireguard interface,
// matches it up with our configuration and IP neighbours, tries to find
// global endpoints for peers that are not connected and not neighbours
// and updates the interface.
func (s *Service) refresh(ctx context.Context, log logr.Logger) error {
	wgDevice, err := s.wgctrl.Device(s.conf.IfaceName)
	if err != nil {
		return fmt.Errorf("get wg device: %w", err)
	}

	neighbours, err := netlink.NeighboursByMAC()
	if err != nil {
		return fmt.Errorf("fetch neighbour addrs: %w", err)
	}

	peers, err := peer.Assemble(wgDevice.Peers, s.conf.Peers, neighbours)
	if err != nil {
		return fmt.Errorf("assemble peer: %w", err)
	}

	wgCfg := wgtypes.Config{Peers: make([]wgtypes.PeerConfig, 0, len(s.conf.Peers))}

	for _, peer := range peers {
		if e := peer.WGConfig(ctx, log, s.resolver); e != nil {
			wgCfg.Peers = append(wgCfg.Peers, *e)
		}
	}

	if len(wgCfg.Peers) != 0 {
		if err := s.wgctrl.ConfigureDevice(s.conf.IfaceName, wgCfg); err != nil {
			return fmt.Errorf("configure wg device %w", err)
		}
	}

	return nil
}
