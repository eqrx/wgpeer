package internal

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
func endpointsEqual(a, b *net.UDPAddr) bool {
	if a == nil && b == nil {
		return true
	}

	if (a == nil) != (b == nil) {
		return false
	}

	return a.IP.Equal(b.IP) && a.Port == b.Port && a.Zone == b.Zone
}
