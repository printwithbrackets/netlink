# netlink (Python bindings)

Python bindings for [NetLink](../../README.md), a secure, lightweight UDP
networking library. These are `ctypes` bindings over the same C library
used by C/C++, Go, and Rust -- a Python client (or server) speaks the
exact same wire protocol as every other language binding, including the
full X25519 + AES-256-GCM handshake and encryption.

## Setup

Build the native library first (from the repository root):

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see the top-level README for flags on your platform
```

This produces `build/libnetlink.so` (or `.dylib` / `.dll`). The Python
bindings look for it, in order:

1. the `NETLINK_LIBRARY_PATH` environment variable, if set
2. `build/libnetlink.*` relative to the repository layout
3. the system library search path (`ctypes.util.find_library`)

## Usage

```python
import netlink

# Server
server = netlink.Server("0.0.0.0", 9000)

# Client
client = netlink.Client()
peer = client.connect("127.0.0.1", 9000)

for event in client.events(timeout=1.0):
    if event.type == netlink.EventType.CONNECTED:
        client.send(peer, channel=0, data=b"hello",
                    delivery=netlink.Delivery.RELIABLE_ORDERED)
    elif event.type == netlink.EventType.DATA:
        print("received:", event.data)
```

Delivery modes (`netlink.Delivery`): `UNRELIABLE`,
`UNRELIABLE_SEQUENCED`, `RELIABLE_UNORDERED`, `RELIABLE_ORDERED` -- see
the top-level README for what each guarantees.

## Running the tests

```sh
cd bindings/python
NETLINK_LIBRARY_PATH=../../build/libnetlink.so pytest tests/ -v
```

The test suite spins up real `Server` and `Client` endpoints over actual
loopback UDP sockets (no mocking) and covers connection setup, all four
delivery modes, fragmentation of large messages, disconnection, and
server-full handling.
