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

// Package netlink contains code that interacts with the generic linux netlink.
package netlink

import (
	"fmt"
	"net/netip"

	"eqrx.net/wgpeer"
	"github.com/vishvananda/netlink"
)

// NeighboursByMAC queries the linux kernel for IPv6 neighbours (link local addresses)
// on links we are connected to and returns them groupes by the MAC address they belong to.
//
// Addresses within groups are not sorted. Returns an error if netlink query failed.
func NeighboursByMAC() (map[string][]netip.AddrPort, error) {
	neighbourSet, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("get ipv6 peers: %w", err)
	}

	linkSet, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("get network interfaces: %w", err)
	}

	links := map[int]string{}
	for _, l := range linkSet {
		links[l.Attrs().Index] = l.Attrs().Name
	}

	neighbours := map[string][]netip.AddrPort{}

	for _, neighbour := range neighbourSet {
		if neighbour.State != netlink.NUD_REACHABLE {
			continue
		}

		ipAddr, addrOk := netip.AddrFromSlice(neighbour.IP)
		if !addrOk {
			panic("addr not ok")
		}

		if !ipAddr.Is6() || !ipAddr.IsLinkLocalUnicast() {
			continue
		}

		mac := neighbour.HardwareAddr.String()

		existingAddrs, ok := neighbours[mac]
		if !ok {
			existingAddrs = make([]netip.AddrPort, 0, 1)
		}

		neighbours[mac] = append(existingAddrs,
			netip.AddrPortFrom(ipAddr.WithZone(links[neighbour.LinkIndex]), wgpeer.Port),
		)
	}

	return neighbours, nil
}
