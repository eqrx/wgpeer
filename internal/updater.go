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

package internal

import (
	"context"
	"fmt"
	"time"

	"eqrx.net/wgpeer/internal/netlink"
	"eqrx.net/wgpeer/internal/peer"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Loop updates the wireguard configuration until the given ctx is cancelled.
func (c *Configuration) Loop(ctx context.Context, log logr.Logger) error {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			err := c.refresh(ctx, log)
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
func (c *Configuration) refresh(ctx context.Context, log logr.Logger) error {
	wgDevice, err := c.wgctrl.Device(c.IfaceName)
	if err != nil {
		return fmt.Errorf("get wg device: %w", err)
	}

	neighbours, err := netlink.NeighboursByMAC()
	if err != nil {
		return fmt.Errorf("fetch neighbour addrs: %w", err)
	}

	err = peer.Merge(c.Peers, wgDevice.Peers, neighbours)
	if err != nil {
		return fmt.Errorf("assemble peer: %w", err)
	}

	wgCfg := wgtypes.Config{Peers: make([]wgtypes.PeerConfig, 0, len(c.Peers))}

	for _, peer := range c.Peers {
		if e := peer.WGConfig(ctx, log, c.resolver); e != nil {
			wgCfg.Peers = append(wgCfg.Peers, *e)
		}
	}

	if len(wgCfg.Peers) != 0 {
		if err := c.wgctrl.ConfigureDevice(c.IfaceName, wgCfg); err != nil {
			return fmt.Errorf("configure wg device %w", err)
		}
	}

	return nil
}
