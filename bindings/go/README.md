# netlink (Go bindings)

Go (cgo) bindings for [NetLink](../../README.md).

**Testing status:** the C core and the Python bindings in this repository
were built and run in the environment that produced them, including a
full test suite over real sockets. This Go binding was **not** -- no Go
toolchain was available in that environment. It's written carefully
against the same C ABI (`include/netlink.h`) the Python bindings were
verified against, using standard cgo patterns, but treat it as needing
its first real `go build && go vet && go test` pass rather than
pre-verified. Contributions confirming (or fixing) it are very welcome.

## Setup

Build the native library first (from the repository root):

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see the top-level README for flags on your platform
```

This produces `build/libnetlink.a`. The cgo preamble in `netlink.go`
points at `../../include` and `../../build` relative to this file
(`${SRCDIR}`); adjust if you vendor this package elsewhere.

## Usage

```go
package main

import (
	"fmt"
	"time"

	netlink "github.com/printwithbrackets/netlink/bindings/go"
)

func main() {
	server, err := netlink.NewServer("0.0.0.0", 9000, netlink.NewConfig())
	if err != nil {
		panic(err)
	}
	defer server.Close()

	for {
		ev, ok := server.PollEvent(time.Second)
		if !ok {
			continue
		}
		switch ev.Type {
		case netlink.EventConnected:
			fmt.Println("peer connected:", ev.Peer)
		case netlink.EventData:
			fmt.Println("received:", string(ev.Data))
			server.Send(ev.Peer, ev.Channel, netlink.ReliableOrdered, ev.Data) // echo
		}
	}
}
```
