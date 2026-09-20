# Cross-language testing guide

This walks through building and running every client/server combination
NetLink supports across languages. All of them speak the exact same wire
protocol (one C core, thin bindings on top), so any client here should
work against any server here without modification.

**What's been verified by running it, in the environment that built this
project:** every combination *involving the C core directly or via the
Python bindings* -- i.e. C client <-> C server, Python client <-> C
server, Python client <-> Python server, and the C/Python examples below
against the C example server. See the top-level README's Testing section
for the exact list.

**What needs your toolchain to verify:** anything involving a Go or Rust
*server*, since no Go or Rust toolchain was available while building this
project. The combinations below are written to work -- the bindings were
built against the exact same C ABI the Python bindings were verified
against, byte-for-byte -- but you're the first to actually compile and
run the Go/Rust side. If something doesn't build or doesn't connect,
that's genuinely useful to report (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## 0. Build the C core first

Every combination below needs this done first, from the repository root:

```sh
make            # Linux with pkg-config finding OpenSSL; see README for
                # the explicit CRYPTO_CFLAGS/CRYPTO_LIBS form otherwise
make examples   # builds build/examples/echo_server and echo_client
```

This produces `build/libnetlink.a` (static, what Go/Rust link against)
and `build/libnetlink.so` (shared, what Python loads at runtime).

## 1. C/C++ client + Go server

Build the Go server:

```sh
cd bindings/go/examples/echo_server
go build -o echo_server .
```

This uses the `replace` directive in that directory's `go.mod` to pull in
the bindings from `../../` locally (no network/publish step needed). If
`go build` can't find `netlink.h` or `libnetlink.a`, double-check step 0
was run from the repo root -- the cgo preamble in `bindings/go/netlink.go`
points at `../../include` and `../../build` relative to itself.

Run the server, then the C client from the repo root in another terminal:

```sh
# terminal 1
./echo_server 9000

# terminal 2, from the repo root
./build/examples/echo_client 127.0.0.1 9000
```

Expected: the client prints `Connected!` and three `Echo received on
channel N: ...` lines (channels 0/1/2, reliable/sequenced/unordered), the
server prints matching `[+] connected` / `[.] echoing` lines.

## 2. Python client + Go server

Same Go server as above. Client:

```sh
cd bindings/python
NETLINK_LIBRARY_PATH=../../build/libnetlink.so python3 examples/echo_client.py 127.0.0.1 9000
```

Expected output is the same three echoes, from the Python side.

## 3. C/C++ client + Rust server

Build and run the Rust server (from `bindings/rust/`):

```sh
cd bindings/rust
cargo run --example echo_server -- 9000
```

`build.rs` links against `../../build/libnetlink.a` by default (override
with the `NETLINK_LIB_DIR` environment variable if needed). If linking
fails looking for `-lcrypto`, make sure OpenSSL's shared library is on
your linker's default search path (it is on virtually every Linux distro
and macOS-with-Homebrew setup once installed).

Then, in another terminal, the same C client as above:

```sh
./build/examples/echo_client 127.0.0.1 9000
```

## 4. Python client + Rust server

Same Rust server as step 3. Client:

```sh
cd bindings/python
NETLINK_LIBRARY_PATH=../../build/libnetlink.so python3 examples/echo_client.py 127.0.0.1 9000
```

## Troubleshooting

- **"Connected!" never prints / times out:** almost always a firewall or
  the server not actually running -- check the server's terminal for a
  "listening on UDP port" line first. NetLink uses UDP, so `nc -u` /
  `ss -lun` are your friends for confirming a socket is actually bound.
- **Go: `undefined reference to nl_server_create` or similar at link
  time:** the static library wasn't built (or `go build` isn't finding
  it) -- rerun `make` from the repo root and confirm
  `build/libnetlink.a` exists.
- **Rust: `cargo` can't find `libcrypto`:** set `CRYPTO_LIBS` when running
  `make` to point at your OpenSSL install (see the top-level README), and
  make sure the same library is discoverable at Rust link time (it uses
  the system default search path via `build.rs`'s
  `cargo:rustc-link-lib=dylib=crypto`, so wherever `make` found it should
  also work for `cargo`).
- **Any combination connects but data doesn't arrive:** check firewalls
  again -- UDP is stateless, so some firewall configurations block the
  server's *replies* even when the initial request got through. Testing
  on `127.0.0.1` (as all the commands above do) sidesteps this; testing
  across real machines may need a firewall rule for the port you chose.
