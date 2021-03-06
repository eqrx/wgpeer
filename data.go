// Package wgpeer defines the data structures used in the configuration file of this project.
package wgpeer

// Port is the default wireguard port.
const Port = 51820

// Configuration is the unmarshalled form of the configuration file and contains all information
// of this node that are required for wgpeer.
type Configuration struct {
	// IfaceName if the wireguard interface we are managing.
	IfaceName string `yaml:"ifaceName"`
	// Peers is the set of peers this node wants to communicate with.
	Peers []PeerConfiguration `yaml:"peers"`
}

// NewConfiguration creates a new Configuration instance with all values set.
func NewConfiguration(ifaceName string, peers ...PeerConfiguration) Configuration {
	return Configuration{ifaceName, peers}
}

// PeerConfiguration defines a peer this nodes wants to connect to vai wireguard.
type PeerConfiguration struct {
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
}

// NewPeer creates a new Peer instance object with all values set.
func NewPeer(public, dnsName string, macs []string) PeerConfiguration {
	return PeerConfiguration{public, dnsName, macs}
}
