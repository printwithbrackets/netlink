//! Integration tests for the Rust bindings: real Server + Client over
//! loopback UDP, speaking the same wire protocol as the C core.
//!
//! Requires the C library to be built first (`make` at the repository
//! root produces `build/libnetlink.a`). Run with:
//!
//! ```sh
//! cd bindings/rust && cargo test
//! ```

use netlink::{Client, Config, Delivery, EventType, PeerId, Server};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

static PORT: AtomicU16 = AtomicU16::new(37100);

fn next_port() -> u16 {
    PORT.fetch_add(1, Ordering::SeqCst)
}

fn wait_for(ep: &netlink::Endpoint, typ: EventType, timeout: Duration) -> netlink::Event {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(ev) = ep.poll_event(Duration::from_millis(50)) {
            if ev.event_type == typ {
                return ev;
            }
        }
    }
    panic!("timed out waiting for event {:?}", typ);
}

struct Pair {
    server: Server,
    client: Client,
    client_peer: PeerId,
    server_peer: PeerId,
}

impl Drop for Pair {
    fn drop(&mut self) {
        // Endpoint Drop destroys handles; explicit order not required.
    }
}

fn connected_pair() -> Pair {
    let port = next_port();
    let server = Server::new("127.0.0.1", port, Config::default()).expect("NewServer");
    let mut client = Client::new(Config::default()).expect("NewClient");
    let client_peer = client.connect("127.0.0.1", port).expect("connect");
    wait_for(&client, EventType::Connected, Duration::from_secs(3));
    let server_ev = wait_for(&server, EventType::Connected, Duration::from_secs(3));
    Pair {
        server,
        client,
        client_peer,
        server_peer: server_ev.peer,
    }
}

#[test]
fn version_is_semver() {
    let v = netlink::version();
    assert!(!v.is_empty(), "version() returned empty");
    assert!(v.contains('.'), "version() = {:?}, expected X.Y.Z", v);
}

#[test]
fn config_defaults() {
    let cfg = Config::default();
    assert_eq!(cfg.channel_count, 4);
    assert_eq!(cfg.max_connections, 64);
    assert_eq!(cfg.connection_timeout_ms, 10000);
    assert_eq!(cfg.keepalive_interval_ms, 1000);
    assert!(cfg.encryption_enabled);
    assert!(cfg.server_name.is_none());
}

#[test]
fn connect_and_echo() {
    let p = connected_pair();

    let msg = b"hello from rust";
    p.client
        .send(p.client_peer, 0, Delivery::ReliableOrdered, msg)
        .expect("send");

    let ev = wait_for(&p.server, EventType::Data, Duration::from_secs(3));
    assert_eq!(ev.peer, p.server_peer);
    assert_eq!(ev.channel, 0);
    assert_eq!(ev.data, msg);

    let reply = b"hi from rust server";
    p.server
        .send(p.server_peer, 0, Delivery::ReliableOrdered, reply)
        .expect("server send");
    let ev = wait_for(&p.client, EventType::Data, Duration::from_secs(3));
    assert_eq!(ev.data, reply);
}

#[test]
fn all_delivery_modes() {
    let p = connected_pair();
    let modes = [
        Delivery::Unreliable,
        Delivery::UnreliableSequenced,
        Delivery::ReliableUnordered,
        Delivery::ReliableOrdered,
    ];
    for (i, mode) in modes.iter().enumerate() {
        let payload = [b'a' + i as u8];
        p.client
            .send(p.client_peer, i as u8, *mode, &payload)
            .expect("send");
        let ev = wait_for(&p.server, EventType::Data, Duration::from_secs(3));
        assert_eq!(ev.channel as usize, i);
        assert_eq!(ev.data, payload);
    }
}

#[test]
fn fragmentation_large_message() {
    let p = connected_pair();
    let big: Vec<u8> = (0..5000).map(|i| ((i * 37 + 3) % 256) as u8).collect();
    p.client
        .send(p.client_peer, 0, Delivery::ReliableOrdered, &big)
        .expect("send");
    let ev = wait_for(&p.server, EventType::Data, Duration::from_secs(5));
    assert_eq!(ev.data, big);
}

#[test]
fn send_ex_and_peer_stats() {
    let p = connected_pair();

    p.client
        .send_ex(
            p.client_peer,
            0,
            Delivery::ReliableOrdered,
            b"urgent",
            netlink::priority::HIGH,
        )
        .expect("send_ex");
    let ev = wait_for(&p.server, EventType::Data, Duration::from_secs(3));
    assert_eq!(ev.data, b"urgent");

    let stats = p.client.peer_stats(p.client_peer).expect("stats for known peer");
    assert!(stats.packets_sent >= 1, "packets_sent = {}", stats.packets_sent);
    assert!(stats.rtt_ms < 2000, "rtt_ms = {}", stats.rtt_ms);

    assert!(p.client.peer_stats(p.client_peer + 999).is_none());

    let caps = p.client.peer_capabilities(p.client_peer).expect("caps for known peer");
    assert!(
        caps & netlink::caps::FLOW_CONTROL != 0,
        "caps = {:#x}, missing FLOW_CONTROL",
        caps
    );
    assert!(p.client.peer_capabilities(p.client_peer + 999).is_none());
}

#[test]
fn peer_count_and_rtt() {
    let p = connected_pair();

    assert_eq!(p.client.peer_count(), 1);
    assert_eq!(p.server.peer_count(), 1);
    assert_eq!(p.client.peer_rtt_ms(p.client_peer + 999), 0);

    // Force a reliable round trip so an RTT sample lands.
    p.client
        .send(p.client_peer, 0, Delivery::ReliableOrdered, b"ping")
        .expect("send");
    wait_for(&p.server, EventType::Data, Duration::from_secs(3));
    p.server
        .send(p.server_peer, 0, Delivery::ReliableOrdered, b"pong")
        .expect("server send");
    wait_for(&p.client, EventType::Data, Duration::from_secs(3));

    let rtt = p.client.peer_rtt_ms(p.client_peer);
    assert!(rtt < 2000, "rtt = {}", rtt);
}

#[test]
fn graceful_disconnect() {
    let p = connected_pair();
    p.client.disconnect(p.client_peer).expect("disconnect");
    let ev = wait_for(&p.server, EventType::Disconnected, Duration::from_secs(3));
    assert!(
        ev.disconnect_reason.is_none(),
        "graceful disconnect should have nil reason, got {:?}",
        ev.disconnect_reason
    );
}

#[test]
fn server_full_denies_second_client() {
    let port = next_port();
    let mut cfg = Config::default();
    cfg.max_connections = 1;
    let server = Server::new("127.0.0.1", port, cfg).expect("NewServer");

    let mut c1 = Client::new(Config::default()).expect("c1");
    let mut c2 = Client::new(Config::default()).expect("c2");

    c1.connect("127.0.0.1", port).expect("c1 connect");
    wait_for(&c1, EventType::Connected, Duration::from_secs(3));
    wait_for(&server, EventType::Connected, Duration::from_secs(3));

    c2.connect("127.0.0.1", port).expect("c2 connect returns immediately");
    let ev = wait_for(&c2, EventType::ConnectFailed, Duration::from_secs(3));
    assert!(
        ev.disconnect_reason.is_some(),
        "expected a disconnect reason on connect failure"
    );
}

#[test]
fn duplicate_connect_rejected() {
    let port = next_port();
    let server = Server::new("127.0.0.1", port, Config::default()).expect("NewServer");
    let mut client = Client::new(Config::default()).expect("NewClient");

    client.connect("127.0.0.1", port).expect("first connect");
    let err = client
        .connect("127.0.0.1", port)
        .expect_err("second connect to same address must fail");
    assert_eq!(err.code, -6, "want NL_ERR_ALREADY_CONNECTED (-6), got {}", err.code);
    assert!(err.message.contains("already connected"), "message = {:?}", err.message);

    // Keep server alive until after the failed connect.
    drop(server);
}

#[test]
fn netlink_error_display_and_error_trait() {
    let e = netlink::NetLinkError {
        code: -6,
        message: "already connected".into(),
    };
    let s = format!("{}", e);
    assert!(s.contains("-6"));
    assert!(s.contains("already connected"));
    // Usable as std::error::Error.
    let _: &dyn std::error::Error = &e;
}
