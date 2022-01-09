package internal

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"

	wgpeer "dev.eqrx.net/wgpeer"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// port is the default wireguard port.
const port = 51820

// errMismatch indicates that wgprobe configuration and current system state are not compatible.
var errMismatch = errors.New("config mismatch")

// peer is a container for the current wireguard configuration of a peer, the information we
// have about it and a list of neighbour endpoints of it.
type peer struct {
	WG             wgtypes.Peer
	Link           wgpeer.Peer
	KnownEndpoints []*net.UDPAddr
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

// neighboursByMAC queries the linux kernel for IPv6 neighbours (link local addresses)
// on links we are connected to and returns them groupes by the MAC address they belong to.
//
// Addresses within groups are not sorted. Returns an error if netlink query failed.
func neighboursByMAC() (map[string][]*net.UDPAddr, error) {
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

	neighbours := map[string][]*net.UDPAddr{}

	for _, neighbour := range neighbourSet {
		if neighbour.State != netlink.NUD_REACHABLE || neighbour.IP.To16() == nil || !neighbour.IP.IsLinkLocalUnicast() {
			continue
		}

		addr := neighbour.HardwareAddr.String()

		existing, ok := neighbours[addr]
		if !ok {
			existing = make([]*net.UDPAddr, 0, 1)
		}

		neighbours[addr] = append(existing, &net.UDPAddr{IP: neighbour.IP, Port: port, Zone: links[neighbour.LinkIndex]})
	}

	return neighbours, nil
}

// combinePeerInfo takes a list of wireguard peer configurations and a list of wgpeer peer configurations, queries
// neighbour endpoint addresses from the kernel and combines them into peer instances. An error is returned if
// netlink access failed or information is inconsistent.
func combinePeerInfo(wgPeerSet []wgtypes.Peer, linkPeerSet []wgpeer.Peer) ([]peer, error) {
	wgPeers, err := wgPeersByPublic(wgPeerSet)
	if err != nil {
		return nil, err
	}

	neighbours, err := neighboursByMAC()
	if err != nil {
		return nil, err
	}

	peers := make([]peer, 0, len(linkPeerSet))

	for _, linkPeer := range linkPeerSet {
		wgPeer, ok := wgPeers[linkPeer.Public]
		if !ok {
			return nil, fmt.Errorf("%w: our peer is not known by wg interface", errMismatch)
		}

		delete(wgPeers, linkPeer.Public)

		endpoints := []*net.UDPAddr{}

		for _, mac := range linkPeer.MACs {
			if addrs, ok := neighbours[mac]; ok {
				sort.Slice(addrs, func(i, j int) bool {
					return bytes.Compare(addrs[i].IP, addrs[j].IP) > 0
				})

				endpoints = append(endpoints, addrs...)
			}
		}

		peers = append(peers, peer{wgPeer, linkPeer, endpoints})
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
