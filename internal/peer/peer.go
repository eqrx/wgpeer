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

// Package peer handles the matching of data in this project.
package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// errMismatch indicates that wgprobe configuration and current system state are not compatible.
var errMismatch = errors.New("config mismatch")

// Peer defines a peer this nodes wants to connect to vai wireguard.
type Peer struct {
	// Public is the base64 encoded WG public key.
	Public string `yaml:"public"`
	// DNSName is the name of the DNS AAAA RR that contains the global endpint of the peer.
	// Is refereshed continuously.
	DNSName string `yaml:"dnsName"`
	// MACs is the list of MAC addresses of the peer. This is used to determine if a link address
	// belongs to it. Multiple MACs may be specified in case the node connects with multiple network
	// cards (may it be with all at the same time or a single one out of the list).
	// If multiple peer addresses are found the one belonging belonging to the earlier specified MAC
	// is preferred.
	MACs []string `yaml:"macs"`

	wg             wgtypes.Peer     `yaml:"-"`
	knownEndpoints []netip.AddrPort `yaml:"-"`
}

// DNSResolver is responsible for resolving a DNS record.
type DNSResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

// wgPeersByPublic creates a mapping of the public key of a wireguard peer to its
// current wireguard configuration. It returns an error if multiple configuration
// entries for the same public key exists in the argument.
func wgPeersByPublic(peers []wgtypes.Peer) (map[string]wgtypes.Peer, error) {
	wgPeers := map[string]wgtypes.Peer{}

	for _, peer := range peers {
		public := peer.PublicKey.String()
		if _, ok := wgPeers[public]; ok {
			return nil, fmt.Errorf("%w: wg reports duplicate peer", errMismatch)
		}

		wgPeers[public] = peer
	}

	return wgPeers, nil
}

// Merge takes a list of wgpeers and a list of wgtypes peers, queries neighbour endpoint addresses from the kernel
// and combines the results into the instances. An error is returned if netlink access failed or information is
// inconsistent.
func Merge(peers []Peer, wgs []wgtypes.Peer, neighs map[string][]netip.AddrPort) error {
	wgPeers, err := wgPeersByPublic(wgs)
	if err != nil {
		return err
	}

	for peerIdx := range peers {
		wgPeer, ok := wgPeers[peers[peerIdx].Public]
		if !ok {
			return fmt.Errorf("%w: our peer is not known by wg interface", errMismatch)
		}

		delete(wgPeers, peers[peerIdx].Public)

		endpoints := []netip.AddrPort{}

		for _, mac := range peers[peerIdx].MACs {
			if addrs, ok := neighs[mac]; ok {
				sort.Slice(addrs, func(i, j int) bool { return addrs[i].Addr().Less(addrs[j].Addr()) })

				endpoints = append(endpoints, addrs...)
			}
		}

		peers[peerIdx].wg = wgPeer
		peers[peerIdx].knownEndpoints = endpoints
	}

	if len(wgPeers) == 0 {
		return nil
	}

	missing := []string{}
	for public := range wgPeers {
		missing = append(missing, public)
	}

	return fmt.Errorf("%w: wg interface has peers configured we don't know: %v", errMismatch, missing)
}
