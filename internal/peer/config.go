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
	"net/netip"
	"time"

	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultPort = 51820
	// HandshakeTimeout specifies the duration after a wireguard handshake is assumed out of date.
	HandshakeTimeout = 140 * time.Second
)

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
	var currentEndpoint, nextEndpoint netip.AddrPort
	if p.wg.Endpoint != nil {
		currentEndpoint = p.wg.Endpoint.AddrPort()
	}

	switch {
	case !p.wg.LastHandshakeTime.IsZero() && time.Since(p.wg.LastHandshakeTime) < HandshakeTimeout:
		// Has handshake, nothing to do.
	case len(p.knownEndpoints) != 0:
		// Does not have a handshake and we know neighbours we can try.
		nextEndpoint = newEndpoint(p.knownEndpoints, currentEndpoint)
	case p.DNSName != "":
		// Neither has a handshake nor know we neighbours we can try but the peer has a DNS name.
		nextEndpoint = p.resolve(ctx, log, resolver, currentEndpoint)
	}

	if nextEndpoint.IsValid() && currentEndpoint != nextEndpoint {
		log.Info(
			"switching endpoint",
			"name", p.DNSName, "from", currentEndpoint, "to", nextEndpoint,
		)

		return &wgtypes.PeerConfig{PublicKey: p.wg.PublicKey, Endpoint: net.UDPAddrFromAddrPort(nextEndpoint)}
	}

	return nil
}

func (p *Peer) resolve(ctx context.Context, log logr.Logger, res DNSResolver, cur netip.AddrPort) netip.AddrPort {
	ips, err := res.LookupIP(ctx, "ip6", p.DNSName)

	switch {
	case err != nil:
		log.Error(err, "peer not resolvable", "publickey", p.Public, "dnsname", p.DNSName)

		return netip.AddrPort{}
	case len(ips) != 0:
		endpoints := make([]netip.AddrPort, 0, len(ips))

		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				panic("ip invalid")
			}

			endpoints = append(endpoints, netip.AddrPortFrom(addr, defaultPort))
		}

		return newEndpoint(endpoints, cur)
	default:
		return netip.AddrPort{}
	}
}
