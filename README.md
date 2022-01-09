[![Go Reference](https://pkg.go.dev/badge/dev.eqrx.net/wgpeer.svg)](https://pkg.go.dev/dev.eqrx.net/wgpeer)
# wgpeer

wgpeer manages the endpoints of peers configured for a wireguard interface. It detects when handshakes with a peer
do not succeed and rotates the remote endpoint between its IP reported by DNS and neighbouring addresses matching its
MACs on shared links.

This project is released under GNU Affero General Public License v3.0, see LICENCE file in this repo for more info.
