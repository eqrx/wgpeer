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
	"net"
)

// newEndpoint picks a new endpoint the the given slice known. It returns nil
// if no new endpoint is available.
//
// Which index will be picked depends on the endpoint current.
// If the current endpoint is present in known the address with the next index
// (looping is returned). If current is nil or not present in known, the first
// index will be returned. known must not be empty or nil.
func newEndpoint(known []*net.UDPAddr, current *net.UDPAddr) *net.UDPAddr {
	if current == nil {
		return known[0]
	}

	if len(known) > 1 {
		for i := range known {
			if endpointsEqual(known[i], current) {
				return known[(i+1)%len(known)]
			}
		}
	}

	if !endpointsEqual(known[0], current) {
		return known[0]
	}

	return nil
}

// endpointsEqual returns true if both given UDP addresses are equal.
//
// Addresses are considered equal if both are nil or the IP, Port and Zone
// field are equal in both instances. A nil and a non nil instance are
// considered unequal.
func endpointsEqual(left, right *net.UDPAddr) bool {
	if left == nil && right == nil {
		return true
	}

	if (left == nil) != (right == nil) {
		return false
	}

	return left.IP.Equal(right.IP) && left.Port == right.Port && left.Zone == right.Zone
}
