# weft-net (Python bindings)

Python bindings for [weft-net](../../README.md), a secure, lightweight UDP
networking library. These are `ctypes` bindings over the same C library
used by C/C++, Go, and Rust -- a Python client (or server) speaks the
exact same wire protocol as every other language binding, including the
full X25519 + AES-256-GCM handshake and encryption.

## Setup

Build the native library first (from the repository root):

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see the top-level README for flags on your platform
```

This produces `build/libweft_net.so` (or `.dylib` / `.dll`). The Python
bindings look for it, in order:

1. the `WEFT_NET_LIBRARY_PATH` environment variable, if set
2. `build/libweft_net.*` relative to the repository layout
3. the system library search path (`ctypes.util.find_library`)

## Usage

```python
import weft_net

# Server
server = weft_net.Server("0.0.0.0", 9000)

# Client
client = weft_net.Client()
peer = client.connect("127.0.0.1", 9000)

for event in client.events(timeout=1.0):
    if event.type == weft_net.EventType.CONNECTED:
        client.send(peer, channel=0, data=b"hello",
                    delivery=weft_net.Delivery.RELIABLE_ORDERED)
    elif event.type == weft_net.EventType.DATA:
        print("received:", event.data)
```

Delivery modes (`weft_net.Delivery`): `UNRELIABLE`,
`UNRELIABLE_SEQUENCED`, `RELIABLE_UNORDERED`, `RELIABLE_ORDERED` -- see
the top-level README for what each guarantees.

## Running the tests

```sh
cd bindings/python
WEFT_NET_LIBRARY_PATH=../../build/libweft_net.so pytest tests/ -v
```

The test suite spins up real `Server` and `Client` endpoints over actual
loopback UDP sockets (no mocking) and covers connection setup, all four
delivery modes, fragmentation of large messages, disconnection, and
server-full handling.
