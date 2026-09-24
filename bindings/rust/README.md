# netlink-rs (Rust bindings)

Rust FFI bindings for [NetLink](../../README.md).

**Testing status:** built and passing real-socket integration tests
(`cargo test`) against the compiled C library. CI runs `cargo build` and
`cargo test` on every push.

## Setup

Build the native library first (from the repository root):

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see the top-level README for flags on your platform
```

This produces `build/libnetlink.a`. `build.rs` links against it from
`../../build` relative to this crate by default; override with the
`NETLINK_LIB_DIR` environment variable if you vendor this crate elsewhere.

## Tests

```sh
cargo test
```

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
