# netlink (Go bindings)

Go (cgo) bindings for [NetLink](../../README.md).

**Testing status:** built, vetted, and passing real-socket integration
tests (`go test ./...`) against the compiled C library. CI runs
`go build`, `go vet`, and `go test` on every push.

## Setup

Build the native library first (from the repository root):

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see the top-level README for flags on your platform
```

This produces `build/libnetlink.a` and `build/libnetlink.so`. The cgo
preamble in `netlink.go` points at `../../include` and `../../build`
relative to this file (`${SRCDIR}`), with an rpath so `go test` finds
the shared library without extra environment variables; adjust if you
vendor this package elsewhere.

## Tests

```sh
go test ./...
```

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
