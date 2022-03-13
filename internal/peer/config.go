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

package peer

import (
	"context"
	"net"
	"time"

	"eqrx.net/wgpeer"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// HandshakeTimeout specifies the duration after a wireguard handshake is assumed out of date.
const HandshakeTimeout = 140 * time.Second

// WGConfig deducts a wireguard PeerConfig instance from a given peer container. It returns nil
// if not change needs to be performed.
//
// It determines this by first checking if we have a recent handshake with the peer. If so no
// change is needed since the connection is working.
// It is then checked if we know a neighbouring endpoint address of the peer. If so and it is
// different from the current endpoint it is selected. If there are multiple endpoints known the
// next one in the list is tried out.
// If both of the previous are false and DNSName is set, try to resolve it and pick the next resolved
// address. Note that endpoints will be tried randomly if your DNS server returns RR in an randomized
// order.
func (p *Peer) WGConfig(ctx context.Context, log logr.Logger, resolver DNSResolver) *wgtypes.PeerConfig {
	var endpoint *net.UDPAddr

	switch {
	case !p.WG.LastHandshakeTime.IsZero() && time.Since(p.WG.LastHandshakeTime) < HandshakeTimeout:
		// Has handshake, nothing to do.
	case len(p.KnownEndpoints) != 0:
		// Does not have a handshake and we know neighbours we can try.
		endpoint = newEndpoint(p.KnownEndpoints, p.WG.Endpoint)
	case p.Config.DNSName != "":
		// Neither has a handshake nor know we neighbours we can try but the peer has a DNS name.
		ips, err := resolver.LookupIP(ctx, "ip6", p.Config.DNSName)
		if err != nil {
			log.Error(err, "peer not resolvable", "publickey", p.Config.Public, "dnsname", p.Config.DNSName)
		} else if len(ips) != 0 {
			endpoints := make([]*net.UDPAddr, 0, len(ips))
			for _, ip := range ips {
				endpoints = append(endpoints, &net.UDPAddr{IP: ip, Port: wgpeer.Port, Zone: ""})
			}

			endpoint = newEndpoint(endpoints, p.WG.Endpoint)
		}
	}

	if endpoint != nil {
		log.Info(
			"switching endpoint",
			"name", p.Config.DNSName, "from", p.WG.Endpoint, "to", endpoint,
		)

		return &wgtypes.PeerConfig{PublicKey: p.WG.PublicKey, Endpoint: endpoint}
	}

	return nil
}
