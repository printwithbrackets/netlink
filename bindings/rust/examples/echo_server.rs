//! echo_server.rs - a NetLink server written in Rust, using the FFI
//! bindings in this crate. Speaks the exact same wire protocol as the C
//! core, so any C/C++, Python, or Go client in this repository can
//! connect to it without modification.
//!
//! Build/run (from bindings/rust/):
//!   cargo run --example echo_server -- 9000

use netlink::{Config, Delivery, EventType, Server};
use std::env;
use std::time::Duration;

fn main() {
    let port: u16 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000);

    let mut cfg = Config::default();
    cfg.server_name = Some("NetLink Rust Example Server".to_string());

    let server = Server::new("0.0.0.0", port, cfg).unwrap_or_else(|e| {
        eprintln!("failed to start server: {}", e);
        std::process::exit(1);
    });

    if let Err(e) = server.enable_discovery(port + 1) {
        eprintln!("discovery not enabled: {}", e);
    }

    println!(
        "NetLink (Rust) echo server listening on UDP port {} (discovery on {})",
        port,
        port + 1
    );
    println!("Press Ctrl+C to stop.");

    loop {
        let ev = match server.poll_event(Duration::from_millis(200)) {
            Some(ev) => ev,
            None => continue,
        };

        match ev.event_type {
            EventType::Connected => {
                println!("[+] peer {} connected from {}:{}", ev.peer, ev.from_host, ev.from_port);
            }
            EventType::Disconnected => {
                println!("[-] peer {} disconnected ({:?})", ev.peer, ev.disconnect_reason);
            }
            EventType::Data => {
                println!(
                    "[.] echoing {} bytes from peer {} on channel {}",
                    ev.data.len(),
                    ev.peer,
                    ev.channel
                );
                // Echo back reliably-ordered regardless of how it arrived,
                // mirroring the C, Python, and Go examples for consistency.
                if let Err(e) = server.send(ev.peer, ev.channel, Delivery::ReliableOrdered, &ev.data) {
                    eprintln!("send failed: {}", e);
                }
            }
            _ => {}
        }
    }
}
