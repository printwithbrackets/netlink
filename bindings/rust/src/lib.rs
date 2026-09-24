//! Rust bindings for the NetLink C library.
//!
//! **Testing status:** the C core and Python bindings in this repository
//! were built and run in the environment that produced them, including a
//! full test suite over real sockets. This Rust binding was **not** -- no
//! Rust toolchain was available in that environment. It's written
//! carefully against the same C ABI (`include/netlink.h`) the Python
//! bindings were verified against byte-for-byte, but treat it as needing
//! its first real `cargo build && cargo test` pass rather than
//! pre-verified. Contributions confirming (or fixing) it are very welcome.
//!
//! # Example
//! ```no_run
//! use netlink::{Client, Config};
//! use std::time::Duration;
//!
//! let mut client = Client::new(Config::default()).unwrap();
//! let peer = client.connect("127.0.0.1", 9000).unwrap();
//! let event = client.wait_connected(Duration::from_secs(5)).unwrap();
//! client.send(peer, 0, netlink::Delivery::ReliableOrdered, b"hello").unwrap();
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::time::{Duration, Instant};

#[allow(non_camel_case_types, dead_code)]
mod raw {
    use std::os::raw::{c_char, c_int};

    pub const NL_OK: c_int = 0;
    pub const NL_SERVER_NAME_MAX: usize = 64;

    #[repr(C)]
    pub struct nl_endpoint_t {
        _private: [u8; 0],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct nl_address_t {
        pub host: [c_char; 64],
        pub port: u16,
        pub family: c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct nl_config_t {
        pub transport: c_int,
        pub family: c_int,
        pub channel_count: u8,
        pub max_connections: u32,
        pub connection_timeout_ms: u32,
        pub keepalive_interval_ms: u32,
        pub encryption_enabled: bool,
        pub server_name: *const c_char,
        // Fields added with protocol v2 (keep in sync with nl_config_t).
        pub max_send_bytes_per_sec: u32,
        pub recv_window_bytes: u32,
        pub capabilities: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct nl_event_t {
        pub event_type: c_int,
        pub peer: u64,
        pub channel: u8,
        pub data: *const u8,
        pub data_len: usize,
        pub disconnect_reason: c_int,
        pub from_address: nl_address_t,
        pub server_name: [c_char; NL_SERVER_NAME_MAX],
        pub server_player_count: u32,
        pub server_max_players: u32,
    }

    extern "C" {
        pub fn nl_version_string() -> *const c_char;
        pub fn nl_error_string(code: c_int) -> *const c_char;
        pub fn nl_config_default(cfg: *mut nl_config_t);

        pub fn nl_server_create(
            bind_addr: *const nl_address_t,
            cfg: *const nl_config_t,
            out_endpoint: *mut *mut nl_endpoint_t,
        ) -> c_int;
        pub fn nl_client_create(cfg: *const nl_config_t, out_endpoint: *mut *mut nl_endpoint_t) -> c_int;
        pub fn nl_connect(ep: *mut nl_endpoint_t, server_addr: *const nl_address_t, out_peer: *mut u64) -> c_int;
        pub fn nl_disconnect(ep: *mut nl_endpoint_t, peer: u64) -> c_int;
        pub fn nl_endpoint_destroy(ep: *mut nl_endpoint_t);

        pub fn nl_send(
            ep: *mut nl_endpoint_t,
            peer: u64,
            channel: u8,
            delivery: c_int,
            data: *const u8,
            len: usize,
        ) -> c_int;
        pub fn nl_send_ex(
            ep: *mut nl_endpoint_t,
            peer: u64,
            channel: u8,
            delivery: c_int,
            data: *const u8,
            len: usize,
            priority: u8,
        ) -> c_int;
        pub fn nl_poll_event(ep: *mut nl_endpoint_t, out: *mut nl_event_t, timeout_ms: c_int) -> bool;

        pub fn nl_discovery_enable(ep: *mut nl_endpoint_t, discovery_port: u16) -> c_int;
        pub fn nl_discovery_probe(ep: *mut nl_endpoint_t, discovery_port: u16, timeout_ms: c_int) -> c_int;

        pub fn nl_peer_rtt_ms(ep: *mut nl_endpoint_t, peer: u64) -> u32;
        pub fn nl_peer_count(ep: *mut nl_endpoint_t) -> u32;
        pub fn nl_peer_stats(ep: *mut nl_endpoint_t, peer: u64, out: *mut nl_peer_stats_t) -> bool;
        pub fn nl_peer_capabilities(ep: *mut nl_endpoint_t, peer: u64, out: *mut u32) -> bool;
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct nl_peer_stats_t {
        pub packets_sent: u64,
        pub packets_received: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub retransmits: u64,
        pub duplicates_received: u64,
        pub rtt_ms: u32,
        pub rtt_var_ms: u32,
        pub rto_ms: u32,
    }
}

/// Delivery guarantee for a sent message. See the top-level README for the
/// precise semantics of each mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Unreliable = 0,
    UnreliableSequenced = 1,
    ReliableUnordered = 2,
    ReliableOrdered = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    None = 0,
    Connected = 1,
    Disconnected = 2,
    Data = 3,
    ConnectFailed = 4,
    DiscoveryReply = 5,
}

impl EventType {
    fn from_raw(v: c_int) -> Self {
        match v {
            1 => EventType::Connected,
            2 => EventType::Disconnected,
            3 => EventType::Data,
            4 => EventType::ConnectFailed,
            5 => EventType::DiscoveryReply,
            _ => EventType::None,
        }
    }
}

/// A peer connection identifier, valid within the endpoint that produced it.
pub type PeerId = u64;

/// Send priorities for `send_ex` (mirrors `NL_PRIORITY_*`).
pub mod priority {
    pub const LOW: u8 = 0;
    pub const NORMAL: u8 = 64;
    pub const HIGH: u8 = 128;
    pub const CRITICAL: u8 = 192;
}

/// Capability bits negotiated in the handshake (mirrors `NL_CAP_*`).
pub mod caps {
    pub const FLOW_CONTROL: u32 = 0x0000_0001;
    pub const PRIORITY: u32 = 0x0000_0002;
    pub const RATE_LIMIT: u32 = 0x0000_0004;
}

/// Snapshot of per-peer counters and RTT estimates (`nl_peer_stats`).
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub retransmits: u64,
    pub duplicates_received: u64,
    pub rtt_ms: u32,
    pub rtt_var_ms: u32,
    pub rto_ms: u32,
}

/// An error returned by the underlying library (a non-OK `nl_result_t`).
#[derive(Debug, Clone)]
pub struct NetLinkError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for NetLinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "netlink error {}: {}", self.code, self.message)
    }
}
impl std::error::Error for NetLinkError {}

fn check(code: c_int) -> Result<(), NetLinkError> {
    if code == raw::NL_OK {
        Ok(())
    } else {
        let msg = unsafe {
            let ptr = raw::nl_error_string(code);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        Err(NetLinkError { code: code as i32, message: msg })
    }
}

/// Endpoint configuration. Use `Config::default()` for the library's
/// defaults (4 channels, 64 max connections, 10s idle timeout, 1s
/// keepalive, encryption on).
#[derive(Debug, Clone)]
pub struct Config {
    pub channel_count: u8,
    pub max_connections: u32,
    pub connection_timeout_ms: u32,
    pub keepalive_interval_ms: u32,
    pub encryption_enabled: bool,
    pub server_name: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut raw_cfg = std::mem::MaybeUninit::<raw::nl_config_t>::uninit();
        unsafe {
            raw::nl_config_default(raw_cfg.as_mut_ptr());
            let raw_cfg = raw_cfg.assume_init();
            Config {
                channel_count: raw_cfg.channel_count,
                max_connections: raw_cfg.max_connections,
                connection_timeout_ms: raw_cfg.connection_timeout_ms,
                keepalive_interval_ms: raw_cfg.keepalive_interval_ms,
                encryption_enabled: raw_cfg.encryption_enabled,
                server_name: None,
            }
        }
    }
}

impl Config {
    fn to_raw(&self, name_storage: &mut Option<CString>) -> raw::nl_config_t {
        let mut raw_cfg = unsafe {
            let mut c = std::mem::MaybeUninit::<raw::nl_config_t>::uninit();
            raw::nl_config_default(c.as_mut_ptr());
            c.assume_init()
        };
        raw_cfg.channel_count = self.channel_count;
        raw_cfg.max_connections = self.max_connections;
        raw_cfg.connection_timeout_ms = self.connection_timeout_ms;
        raw_cfg.keepalive_interval_ms = self.keepalive_interval_ms;
        raw_cfg.encryption_enabled = self.encryption_enabled;
        if let Some(name) = &self.server_name {
            let cstr = CString::new(name.as_str()).unwrap_or_default();
            raw_cfg.server_name = cstr.as_ptr();
            *name_storage = Some(cstr); // keep alive until nl_server_create returns
        }
        raw_cfg
    }
}

fn make_address(host: &str, port: u16) -> raw::nl_address_t {
    let mut addr = raw::nl_address_t {
        host: [0 as c_char; 64],
        port,
        family: 0, // NL_AF_UNSPEC
    };
    let bytes = host.as_bytes();
    let n = bytes.len().min(addr.host.len() - 1);
    for i in 0..n {
        addr.host[i] = bytes[i] as c_char;
    }
    addr
}

/// A received event. `data` is an owned copy (the underlying C buffer is
/// only valid until the next poll call, so it's copied out here).
#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: EventType,
    pub peer: PeerId,
    pub channel: u8,
    pub data: Vec<u8>,
    pub disconnect_reason: Option<NetLinkError>,
    pub from_host: String,
    pub from_port: u16,
    pub server_name: String,
    pub server_player_count: u32,
    pub server_max_players: u32,
}

fn event_from_raw(raw_ev: &raw::nl_event_t) -> Event {
    let data = if !raw_ev.data.is_null() && raw_ev.data_len > 0 {
        unsafe { std::slice::from_raw_parts(raw_ev.data, raw_ev.data_len).to_vec() }
    } else {
        Vec::new()
    };
    let from_host = unsafe { CStr::from_ptr(raw_ev.from_address.host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let server_name = unsafe { CStr::from_ptr(raw_ev.server_name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let disconnect_reason = if raw_ev.disconnect_reason != raw::NL_OK {
        check(raw_ev.disconnect_reason).err()
    } else {
        None
    };
    Event {
        event_type: EventType::from_raw(raw_ev.event_type),
        peer: raw_ev.peer,
        channel: raw_ev.channel,
        data,
        disconnect_reason,
        from_host,
        from_port: raw_ev.from_address.port,
        server_name,
        server_player_count: raw_ev.server_player_count,
        server_max_players: raw_ev.server_max_players,
    }
}

/// Shared functionality between `Server` and `Client`.
pub struct Endpoint {
    handle: *mut raw::nl_endpoint_t,
}

// The underlying C endpoint is internally thread-safe (see include/netlink.h);
// it's sound to share/move handles across Rust threads.
unsafe impl Send for Endpoint {}
unsafe impl Sync for Endpoint {}

impl Endpoint {
    /// Enqueue `data` for delivery to `peer` on `channel` with the given
    /// delivery guarantee. Safe to call from any thread.
    pub fn send(&self, peer: PeerId, channel: u8, delivery: Delivery, data: &[u8]) -> Result<(), NetLinkError> {
        let ptr = if data.is_empty() { std::ptr::null() } else { data.as_ptr() };
        let res = unsafe { raw::nl_send(self.handle, peer, channel, delivery as c_int, ptr, data.len()) };
        check(res)
    }

    /// Like [`send`](Self::send), with an explicit priority (0..255; see
    /// [`priority`]). When the send window is closed, higher-priority
    /// messages flush first as budget opens.
    pub fn send_ex(
        &self,
        peer: PeerId,
        channel: u8,
        delivery: Delivery,
        data: &[u8],
        priority: u8,
    ) -> Result<(), NetLinkError> {
        let ptr = if data.is_empty() { std::ptr::null() } else { data.as_ptr() };
        let res = unsafe { raw::nl_send_ex(self.handle, peer, channel, delivery as c_int, ptr, data.len(), priority) };
        check(res)
    }

    /// Wait up to `timeout` for the next event. A zero timeout returns
    /// immediately if nothing is queued.
    pub fn poll_event(&self, timeout: Duration) -> Option<Event> {
        let mut raw_ev = unsafe { std::mem::zeroed::<raw::nl_event_t>() };
        let ms = timeout.as_millis().min(i32::MAX as u128) as c_int;
        let got = unsafe { raw::nl_poll_event(self.handle, &mut raw_ev, ms) };
        if got {
            Some(event_from_raw(&raw_ev))
        } else {
            None
        }
    }

    /// Gracefully close a connection.
    pub fn disconnect(&self, peer: PeerId) -> Result<(), NetLinkError> {
        check(unsafe { raw::nl_disconnect(self.handle, peer) })
    }

    pub fn peer_rtt_ms(&self, peer: PeerId) -> u32 {
        unsafe { raw::nl_peer_rtt_ms(self.handle, peer) }
    }

    pub fn peer_count(&self) -> u32 {
        unsafe { raw::nl_peer_count(self.handle) }
    }

    /// Snapshot of per-peer counters and RTT estimates. Returns `None`
    /// if `peer` is not a currently-known connection.
    pub fn peer_stats(&self, peer: PeerId) -> Option<PeerStats> {
        let mut raw_stats = unsafe { std::mem::zeroed::<raw::nl_peer_stats_t>() };
        let ok = unsafe { raw::nl_peer_stats(self.handle, peer, &mut raw_stats) };
        if !ok {
            return None;
        }
        Some(PeerStats {
            packets_sent: raw_stats.packets_sent,
            packets_received: raw_stats.packets_received,
            bytes_sent: raw_stats.bytes_sent,
            bytes_received: raw_stats.bytes_received,
            retransmits: raw_stats.retransmits,
            duplicates_received: raw_stats.duplicates_received,
            rtt_ms: raw_stats.rtt_ms,
            rtt_var_ms: raw_stats.rtt_var_ms,
            rto_ms: raw_stats.rto_ms,
        })
    }

    /// Negotiated `NL_CAP_*` bitmask with this peer. Returns `None` if
    /// `peer` is not a currently-known connection.
    pub fn peer_capabilities(&self, peer: PeerId) -> Option<u32> {
        let mut caps: u32 = 0;
        let ok = unsafe { raw::nl_peer_capabilities(self.handle, peer, &mut caps) };
        if ok { Some(caps) } else { None }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { raw::nl_endpoint_destroy(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

/// A server endpoint: binds a UDP socket and accepts incoming connections.
pub struct Server {
    inner: Endpoint,
}

impl std::ops::Deref for Server {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint {
        &self.inner
    }
}

impl Server {
    /// Bind to `host:port` and start accepting connections in a background thread.
    pub fn new(host: &str, port: u16, config: Config) -> Result<Self, NetLinkError> {
        let addr = make_address(host, port);
        let mut name_storage = None;
        let raw_cfg = config.to_raw(&mut name_storage);
        let mut handle: *mut raw::nl_endpoint_t = std::ptr::null_mut();
        let res = unsafe { raw::nl_server_create(&addr, &raw_cfg, &mut handle) };
        check(res)?;
        Ok(Server { inner: Endpoint { handle } })
    }

    /// Start responding to LAN discovery broadcasts on `discovery_port`.
    pub fn enable_discovery(&self, discovery_port: u16) -> Result<(), NetLinkError> {
        check(unsafe { raw::nl_discovery_enable(self.inner.handle, discovery_port) })
    }
}

/// A client endpoint: initiates outbound connections.
pub struct Client {
    inner: Endpoint,
}

impl std::ops::Deref for Client {
    type Target = Endpoint;
    fn deref(&self) -> &Endpoint {
        &self.inner
    }
}

impl Client {
    pub fn new(config: Config) -> Result<Self, NetLinkError> {
        let mut name_storage = None;
        let raw_cfg = config.to_raw(&mut name_storage);
        let mut handle: *mut raw::nl_endpoint_t = std::ptr::null_mut();
        let res = unsafe { raw::nl_client_create(&raw_cfg, &mut handle) };
        check(res)?;
        Ok(Client { inner: Endpoint { handle } })
    }

    /// Begin connecting to `host:port`. Returns immediately with the peer
    /// id that will identify this connection; wait for `Connected` (or
    /// `ConnectFailed`) via `poll_event` or `wait_connected`.
    pub fn connect(&mut self, host: &str, port: u16) -> Result<PeerId, NetLinkError> {
        let addr = make_address(host, port);
        let mut peer: u64 = 0;
        let res = unsafe { raw::nl_connect(self.inner.handle, &addr, &mut peer) };
        check(res)?;
        Ok(peer)
    }

    /// Broadcast a LAN discovery probe; replies arrive as `DiscoveryReply`
    /// events over subsequent `poll_event` calls.
    pub fn probe_lan(&self, discovery_port: u16, timeout: Duration) -> Result<(), NetLinkError> {
        check(unsafe {
            raw::nl_discovery_probe(self.inner.handle, discovery_port, timeout.as_millis() as c_int)
        })
    }

    /// Block (polling internally) until the connection succeeds or fails,
    /// or `timeout` elapses.
    pub fn wait_connected(&self, timeout: Duration) -> Result<Event, NetLinkError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(ev) = self.inner.poll_event(Duration::from_millis(100)) {
                if ev.event_type == EventType::Connected || ev.event_type == EventType::ConnectFailed {
                    return Ok(ev);
                }
            }
        }
        Err(NetLinkError { code: -12, message: "timed out waiting to connect".to_string() })
    }
}

/// Returns the library's version string (e.g. "1.0.0").
pub fn version() -> String {
    unsafe { CStr::from_ptr(raw::nl_version_string()).to_string_lossy().into_owned() }
}
