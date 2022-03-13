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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"

	"eqrx.net/wgpeer"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// errMismatch indicates that wgprobe configuration and current system state are not compatible.
var errMismatch = errors.New("config mismatch")

// Peer is a container for the current wireguard configuration of a peer, the information we
// have about it and a list of neighbour endpoints of it.
type Peer struct {
	WG             wgtypes.Peer
	Config         wgpeer.PeerConfiguration
	KnownEndpoints []*net.UDPAddr
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

// Assemble takes a list of wireguard peer configurations and a list of wgpeer peer configurations, queries
// neighbour endpoint addresses from the kernel and combines them into peer instances. An error is returned if
// netlink access failed or information is inconsistent.
func Assemble(wgs []wgtypes.Peer, confs []wgpeer.PeerConfiguration, neighs map[string][]*net.UDPAddr) ([]Peer, error) {
	wgPeers, err := wgPeersByPublic(wgs)
	if err != nil {
		return nil, err
	}

	peers := make([]Peer, 0, len(confs))

	for _, linkPeer := range confs {
		wgPeer, ok := wgPeers[linkPeer.Public]
		if !ok {
			return nil, fmt.Errorf("%w: our peer is not known by wg interface", errMismatch)
		}

		delete(wgPeers, linkPeer.Public)

		endpoints := []*net.UDPAddr{}

		for _, mac := range linkPeer.MACs {
			if addrs, ok := neighs[mac]; ok {
				sort.Slice(addrs, func(i, j int) bool {
					return bytes.Compare(addrs[i].IP, addrs[j].IP) > 0
				})

				endpoints = append(endpoints, addrs...)
			}
		}

		peers = append(peers, Peer{wgPeer, linkPeer, endpoints})
	}

	if len(wgPeers) == 0 {
		return peers, nil
	}

	missing := []string{}
	for public := range wgPeers {
		missing = append(missing, public)
	}

	return nil, fmt.Errorf("%w: wg interface has peers configured we don't know: %v", errMismatch, missing)
}
