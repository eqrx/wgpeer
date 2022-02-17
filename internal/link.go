package internal

import (
	"context"
	"fmt"
	"net"
	"time"

	"dev.eqrx.net/wgpeer"
	"github.com/go-logr/logr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// handshakeTimeout specifies the duration after a wireguard handshake is assumed out of date.
const handshakeTimeout = 140 * time.Second

// link is a helper struct that bundles all the common handles.
type link struct {
	// resolver is the DNS resolver used for quering global endpoints.
	resolver *net.Resolver
	// conf contains the configuration of this node.
	conf wgpeer.Configuration
	// wgctrl is the netlink client to configure wireguard interfaces.
	wgctrl *wgctrl.Client
}

// loop updates the wireguard configuration until the given ctx is cancelled.
func (l *link) loop(ctx context.Context, log logr.Logger) error {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			err := l.refresh(ctx, log)
			if err != nil {
				return err
			}

			timer.Reset(handshakeTimeout)
		}
	}
}

// refresh queries the current state of the managed wireguard interface,
// matches it up with our configuration and IP neighbours, tries to find
// global endpoints for peers that are not connected and not neighbours
// and updates the interface.
func (l *link) refresh(ctx context.Context, log logr.Logger) error {
	wgDevice, err := l.wgctrl.Device(l.conf.IfaceName)
	if err != nil {
		return fmt.Errorf("get wg device: %w", err)
	}

	peers, err := combinePeerInfo(wgDevice.Peers, l.conf.Peers)
	if err != nil {
		return err
	}

	wgCfg := wgtypes.Config{Peers: make([]wgtypes.PeerConfig, 0, len(l.conf.Peers))}

	for _, peer := range peers {
		if e := l.wgPeerConfigFromPeer(ctx, log, peer); e != nil {
			wgCfg.Peers = append(wgCfg.Peers, *e)
		}
	}

	if len(wgCfg.Peers) != 0 {
		if err := l.wgctrl.ConfigureDevice(l.conf.IfaceName, wgCfg); err != nil {
			return fmt.Errorf("configure wg device %w", err)
		}
	}

	return nil
}

// peerConfigFromPeer deducts a wireguard PeerConfig instance from a given peer container. It returns nil
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
func (l *link) wgPeerConfigFromPeer(ctx context.Context, log logr.Logger, peer peer) *wgtypes.PeerConfig {
	var endpoint *net.UDPAddr

	switch {
	case !peer.WG.LastHandshakeTime.IsZero() && time.Since(peer.WG.LastHandshakeTime) < handshakeTimeout:
		// Has handshake, nothing to do.
	case len(peer.KnownEndpoints) != 0:
		// Does not have a handshake and we know neighbours we can try.
		endpoint = newEndpoint(peer.KnownEndpoints, peer.WG.Endpoint)
	case peer.Link.DNSName != "":
		// Neither has a handshake nor know we neighbours we can try but the peer has a DNS name.
		ips, err := l.resolver.LookupIP(ctx, "ip6", peer.Link.DNSName)
		if err != nil {
			log.Error(err, "peer not resolvable", "publickey", peer.Link.Public, "dnsname", peer.Link.DNSName)
		} else if len(ips) != 0 {
			endpoints := make([]*net.UDPAddr, 0, len(ips))
			for _, ip := range ips {
				endpoints = append(endpoints, &net.UDPAddr{IP: ip, Port: port, Zone: ""})
			}

			endpoint = newEndpoint(endpoints, peer.WG.Endpoint)
		}
	}

	if endpoint != nil {
		log.Info(
			"switching endpoint",
			"name", peer.Link.DNSName, "public", peer.Link.Public, "from", peer.WG.Endpoint.String(), "to", endpoint,
		)

		return &wgtypes.PeerConfig{PublicKey: peer.WG.PublicKey, Endpoint: endpoint}
	}

	return nil
}
