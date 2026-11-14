# weft-net (Go bindings)

Go (cgo) bindings for [weft-net](../../README.md).

**Testing status:** built, vetted, and passing real-socket integration
tests (`go test ./...`) against the compiled C library. CI runs
`go build`, `go vet`, a `gofmt` check, and `go test` on every push.

## Setup

Build the native library first (from the repository root):

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see the top-level README for flags on your platform
```

This produces `build/libweft_net.a` and `build/libweft_net.so`. The cgo
preamble in `weftnet.go` points at `../../include` and `../../build`
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

	weftnet "github.com/printwithbrackets/weft-net/bindings/go"
)

func main() {
	server, err := weftnet.NewServer("0.0.0.0", 9000, weftnet.NewConfig())
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
		case weftnet.EventConnected:
			fmt.Println("peer connected:", ev.Peer)
		case weftnet.EventData:
			fmt.Println("received:", string(ev.Data))
			server.Send(ev.Peer, ev.Channel, weftnet.ReliableOrdered, ev.Data) // echo
		}
	}
}
```
