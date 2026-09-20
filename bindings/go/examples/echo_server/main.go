// echo_server.go - a NetLink server written in Go, using the cgo bindings
// in bindings/go. Speaks the exact same wire protocol as the C core, so
// any C/C++, Python, or Rust client in this repository can connect to it
// without modification.
//
// Build (from bindings/go/examples/echo_server/):
//   go build -o echo_server .
// Run:
//   ./echo_server 9000
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	netlink "github.com/yourusername/netlink/bindings/go"
)

func main() {
	port := uint16(9000)
	if len(os.Args) > 1 {
		p, err := strconv.Atoi(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid port:", os.Args[1])
			os.Exit(1)
		}
		port = uint16(p)
	}

	cfg := netlink.NewConfig()
	cfg.ServerName = "NetLink Go Example Server"

	server, err := netlink.NewServer("0.0.0.0", port, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to start server:", err)
		os.Exit(1)
	}
	defer server.Close()

	if err := server.EnableDiscovery(port + 1); err != nil {
		fmt.Fprintln(os.Stderr, "discovery not enabled:", err)
	}

	fmt.Printf("NetLink (Go) echo server listening on UDP port %d (discovery on %d)\n", port, port+1)
	fmt.Println("Press Ctrl+C to stop.")

	for {
		ev, ok := server.PollEvent(200 * time.Millisecond)
		if !ok {
			continue
		}

		switch ev.Type {
		case netlink.EventConnected:
			fmt.Printf("[+] peer %d connected from %s:%d\n", ev.Peer, ev.FromHost, ev.FromPort)
		case netlink.EventDisconnected:
			fmt.Printf("[-] peer %d disconnected (%v)\n", ev.Peer, ev.DisconnectReason)
		case netlink.EventData:
			fmt.Printf("[.] echoing %d bytes from peer %d on channel %d\n", len(ev.Data), ev.Peer, ev.Channel)
			// Echo back reliably-ordered regardless of how it arrived,
			// mirroring the C and Python examples for consistency.
			if err := server.Send(ev.Peer, ev.Channel, netlink.ReliableOrdered, ev.Data); err != nil {
				fmt.Fprintln(os.Stderr, "send failed:", err)
			}
		}
	}
}
