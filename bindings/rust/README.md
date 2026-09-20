# netlink-rs (Rust bindings)

Rust FFI bindings for [NetLink](../../README.md).

**Testing status:** the C core and Python bindings in this repository
were built and run in the environment that produced them, including a
full test suite over real sockets. This Rust binding was **not** -- no
Rust toolchain was available in that environment. It's written carefully
against the same C ABI (`include/netlink.h`) the Python bindings were
verified against byte-for-byte -- the raw `extern "C"` declarations mirror
the header's struct layouts field-for-field, and the safe wrapper follows
standard FFI ownership patterns (owned `CString`s kept alive across calls,
`Drop` for cleanup, data copied out of borrowed event buffers). But treat
it as needing its first real `cargo build && cargo test` pass rather than
pre-verified. Contributions confirming (or fixing) it are very welcome.

## Setup

Build the native library first (from the repository root):

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see the top-level README for flags on your platform
```

This produces `build/libnetlink.a`. `build.rs` links against it from
`../../build` relative to this crate by default; override with the
`NETLINK_LIB_DIR` environment variable if you vendor this crate elsewhere.

## Usage

```rust
use netlink::{Client, Config, Delivery};
use std::time::Duration;

let mut client = Client::new(Config::default())?;
let peer = client.connect("127.0.0.1", 9000)?;
client.wait_connected(Duration::from_secs(5))?;

client.send(peer, 0, Delivery::ReliableOrdered, b"hello")?;

loop {
    if let Some(event) = client.poll_event(Duration::from_secs(1)) {
        println!("{:?}", event);
    }
}
```
