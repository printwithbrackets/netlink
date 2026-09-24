"""
netlink - Python bindings for the NetLink C library.

These bindings load libnetlink (built via the top-level Makefile:
`make` produces build/libnetlink.so) with ctypes and wrap it in a small,
Pythonic API. The wire protocol, encryption, reliability, and all other
protocol logic live entirely in the C library -- this module is just a
thin, careful translation of its ABI, so a Python client and a C/Go/Rust
peer using the same library are fully wire-compatible.

Example:
    import netlink

    client = netlink.Client()
    peer = client.connect("127.0.0.1", 9000)

    for event in client.events(timeout=1.0):
        if event.type == netlink.EventType.CONNECTED:
            client.send(peer, channel=0, data=b"hello", delivery=netlink.Delivery.RELIABLE_ORDERED)
        elif event.type == netlink.EventType.DATA:
            print("got", event.data)
"""

from __future__ import annotations

import ctypes
import ctypes.util
import enum
import os
import platform
import time
from dataclasses import dataclass
from typing import Iterator, Optional

__version__ = "1.0.0"

__all__ = [
    "Delivery", "EventType", "AddressFamily", "Transport", "Priority",
    "NetLinkError", "Event", "Config", "Endpoint", "Server", "Client",
    "PeerStats", "version", "__version__",
]

# --------------------------------------------------------------------------
# Priority constants (mirrors include/netlink.h -- keep in sync)
# --------------------------------------------------------------------------

class Priority:
    LOW = 0
    NORMAL = 64
    HIGH = 128
    CRITICAL = 192


# Capability bits (mirrors NL_CAP_* -- keep in sync).
CapFlowControl = 0x00000001
CapPriority = 0x00000002
CapRateLimit = 0x00000004

# --------------------------------------------------------------------------
# Library loading
# --------------------------------------------------------------------------

def _find_library() -> str:
    env = os.environ.get("NETLINK_LIBRARY_PATH")
    if env and os.path.exists(env):
        return env

    system = platform.system()
    names = {
        "Linux": "libnetlink.so",
        "Darwin": "libnetlink.dylib",
        "Windows": "netlink.dll",
    }.get(system, "libnetlink.so")

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "..", "..", "build", names),  # repo layout: bindings/python/netlink/
        os.path.join(here, names),
        names,
    ]
    for c in candidates:
        if os.path.exists(c):
            return c

    found = ctypes.util.find_library("netlink")
    if found:
        return found

    raise OSError(
        "Could not locate the NetLink shared library. Build it first with "
        "`make` in the repository root (produces build/libnetlink.so), or "
        "set the NETLINK_LIBRARY_PATH environment variable to its path."
    )


_lib = ctypes.CDLL(_find_library())

# --------------------------------------------------------------------------
# Enums (mirrors include/netlink.h exactly -- keep in sync)
# --------------------------------------------------------------------------

class Delivery(enum.IntEnum):
    UNRELIABLE = 0
    UNRELIABLE_SEQUENCED = 1
    RELIABLE_UNORDERED = 2
    RELIABLE_ORDERED = 3


class AddressFamily(enum.IntEnum):
    UNSPEC = 0
    INET = 4
    INET6 = 6


class Transport(enum.IntEnum):
    UDP = 0
    WEBSOCKET = 1


class EventType(enum.IntEnum):
    NONE = 0
    CONNECTED = 1
    DISCONNECTED = 2
    DATA = 3
    CONNECT_FAILED = 4
    DISCOVERY_REPLY = 5


class NetLinkError(Exception):
    """Raised for library calls that return a non-OK nl_result_t."""
    def __init__(self, code: int):
        self.code = code
        message = _lib.nl_error_string(ctypes.c_int(code))
        super().__init__(message.decode("utf-8") if message else f"error {code}")


# --------------------------------------------------------------------------
# ctypes struct definitions (must match include/netlink.h byte-for-byte)
# --------------------------------------------------------------------------

NL_SERVER_NAME_MAX = 64


class _Address(ctypes.Structure):
    _fields_ = [
        ("host", ctypes.c_char * 64),
        ("port", ctypes.c_uint16),
        ("family", ctypes.c_int),
    ]


class _Config(ctypes.Structure):
    _fields_ = [
        ("transport", ctypes.c_int),
        ("family", ctypes.c_int),
        ("channel_count", ctypes.c_uint8),
        ("max_connections", ctypes.c_uint32),
        ("connection_timeout_ms", ctypes.c_uint32),
        ("keepalive_interval_ms", ctypes.c_uint32),
        ("encryption_enabled", ctypes.c_bool),
        ("server_name", ctypes.c_char_p),
        # Fields added with protocol v2 (keep in sync with nl_config_t).
        ("max_send_bytes_per_sec", ctypes.c_uint32),
        ("recv_window_bytes", ctypes.c_uint32),
        ("capabilities", ctypes.c_uint32),
    ]


class _Event(ctypes.Structure):
    _fields_ = [
        ("event_type", ctypes.c_int),
        ("peer", ctypes.c_uint64),
        ("channel", ctypes.c_uint8),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("data_len", ctypes.c_size_t),
        ("disconnect_reason", ctypes.c_int),
        ("from_address", _Address),
        ("server_name", ctypes.c_char * NL_SERVER_NAME_MAX),
        ("server_player_count", ctypes.c_uint32),
        ("server_max_players", ctypes.c_uint32),
    ]


class _PeerStats(ctypes.Structure):
    _fields_ = [
        ("packets_sent", ctypes.c_uint64),
        ("packets_received", ctypes.c_uint64),
        ("bytes_sent", ctypes.c_uint64),
        ("bytes_received", ctypes.c_uint64),
        ("retransmits", ctypes.c_uint64),
        ("duplicates_received", ctypes.c_uint64),
        ("rtt_ms", ctypes.c_uint32),
        ("rtt_var_ms", ctypes.c_uint32),
        ("rto_ms", ctypes.c_uint32),
    ]


# --------------------------------------------------------------------------
# Function signatures
# --------------------------------------------------------------------------

_lib.nl_error_string.argtypes = [ctypes.c_int]
_lib.nl_error_string.restype = ctypes.c_char_p

_lib.nl_version_string.argtypes = []
_lib.nl_version_string.restype = ctypes.c_char_p

_lib.nl_config_default.argtypes = [ctypes.POINTER(_Config)]
_lib.nl_config_default.restype = None

_lib.nl_server_create.argtypes = [ctypes.POINTER(_Address), ctypes.POINTER(_Config), ctypes.POINTER(ctypes.c_void_p)]
_lib.nl_server_create.restype = ctypes.c_int

_lib.nl_client_create.argtypes = [ctypes.POINTER(_Config), ctypes.POINTER(ctypes.c_void_p)]
_lib.nl_client_create.restype = ctypes.c_int

_lib.nl_connect.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Address), ctypes.POINTER(ctypes.c_uint64)]
_lib.nl_connect.restype = ctypes.c_int

_lib.nl_disconnect.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
_lib.nl_disconnect.restype = ctypes.c_int

_lib.nl_endpoint_destroy.argtypes = [ctypes.c_void_p]
_lib.nl_endpoint_destroy.restype = None

_lib.nl_send.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint8, ctypes.c_int,
                         ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
_lib.nl_send.restype = ctypes.c_int

_lib.nl_send_ex.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint8, ctypes.c_int,
                            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint8]
_lib.nl_send_ex.restype = ctypes.c_int

_lib.nl_poll_event.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Event), ctypes.c_int]
_lib.nl_poll_event.restype = ctypes.c_bool

_lib.nl_discovery_enable.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
_lib.nl_discovery_enable.restype = ctypes.c_int

_lib.nl_discovery_probe.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_int]
_lib.nl_discovery_probe.restype = ctypes.c_int

_lib.nl_peer_rtt_ms.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
_lib.nl_peer_rtt_ms.restype = ctypes.c_uint32

_lib.nl_peer_count.argtypes = [ctypes.c_void_p]
_lib.nl_peer_count.restype = ctypes.c_uint32

_lib.nl_peer_stats.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(_PeerStats)]
_lib.nl_peer_stats.restype = ctypes.c_bool

_lib.nl_peer_capabilities.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32)]
_lib.nl_peer_capabilities.restype = ctypes.c_bool


def _check(code: int) -> None:
    if code != 0:
        raise NetLinkError(code)


def version() -> str:
    """Return the loaded C library's version string (e.g. "1.0.0")."""
    raw = _lib.nl_version_string()
    return raw.decode("utf-8") if raw else ""


# --------------------------------------------------------------------------
# Public, Pythonic wrapper
# --------------------------------------------------------------------------

@dataclass
class Event:
    type: EventType
    peer: int
    channel: int = 0
    data: bytes = b""
    disconnect_reason: int = 0
    address: Optional[tuple] = None
    server_name: str = ""
    server_player_count: int = 0
    server_max_players: int = 0

    @staticmethod
    def _from_raw(raw: _Event) -> "Event":
        data = b""
        if raw.event_type == EventType.DATA.value and raw.data_len > 0:
            data = bytes(ctypes.cast(raw.data, ctypes.POINTER(ctypes.c_uint8 * raw.data_len)).contents)
        address = None
        if raw.from_address.host:
            address = (raw.from_address.host.decode("utf-8", "replace"), raw.from_address.port)
        return Event(
            type=EventType(raw.event_type),
            peer=raw.peer,
            channel=raw.channel,
            data=data,
            disconnect_reason=raw.disconnect_reason,
            address=address,
            server_name=raw.server_name.decode("utf-8", "replace"),
            server_player_count=raw.server_player_count,
            server_max_players=raw.server_max_players,
        )


@dataclass
class PeerStats:
    """Snapshot of per-peer counters and RTT estimates (nl_peer_stats)."""
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    retransmits: int
    duplicates_received: int
    rtt_ms: int
    rtt_var_ms: int
    rto_ms: int


@dataclass
class Config:
    channel_count: int = 4
    max_connections: int = 64
    connection_timeout_ms: int = 10000
    keepalive_interval_ms: int = 1000
    encryption_enabled: bool = True
    server_name: str = ""
    family: AddressFamily = AddressFamily.UNSPEC

    def _to_raw(self) -> _Config:
        raw = _Config()
        _lib.nl_config_default(ctypes.byref(raw))
        raw.channel_count = self.channel_count
        raw.max_connections = self.max_connections
        raw.connection_timeout_ms = self.connection_timeout_ms
        raw.keepalive_interval_ms = self.keepalive_interval_ms
        raw.encryption_enabled = self.encryption_enabled
        raw.family = int(self.family)
        self._name_buf = self.server_name.encode("utf-8")  # keep alive: c_char_p doesn't own it
        raw.server_name = self._name_buf if self.server_name else None
        return raw


def _make_address(host: str, port: int, family: AddressFamily = AddressFamily.UNSPEC) -> _Address:
    addr = _Address()
    addr.host = host.encode("utf-8")
    addr.port = port
    addr.family = int(family)
    return addr


class Endpoint:
    """Base class for Server and Client; not instantiated directly."""

    def __init__(self):
        self._handle: Optional[ctypes.c_void_p] = None

    def send(self, peer: int, channel: int, data: bytes, delivery: Delivery = Delivery.RELIABLE_ORDERED) -> None:
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        _check(_lib.nl_send(self._handle, peer, channel, int(delivery), buf, len(data)))

    def send_ex(self, peer: int, channel: int, data: bytes, delivery: Delivery = Delivery.RELIABLE_ORDERED,
                priority: int = Priority.NORMAL) -> None:
        """Like send(), with an explicit priority (0..255; see Priority)."""
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        _check(_lib.nl_send_ex(self._handle, peer, channel, int(delivery), buf, len(data), priority))

    def disconnect(self, peer: int) -> None:
        _check(_lib.nl_disconnect(self._handle, peer))

    def poll(self, timeout: float = 0.0) -> Optional[Event]:
        """Poll for a single event. timeout is in seconds; negative blocks forever."""
        raw = _Event()
        timeout_ms = -1 if timeout < 0 else int(timeout * 1000)
        if _lib.nl_poll_event(self._handle, ctypes.byref(raw), timeout_ms):
            return Event._from_raw(raw)
        return None

    def events(self, timeout: float = 1.0) -> Iterator[Event]:
        """Convenience generator: yields events forever, polling with the
        given per-call timeout (so a caller can also do other periodic
        work between yields when nothing arrives -- this generator simply
        loops, so plain `for event in ep.events(): ...` blocks until each
        event arrives)."""
        while True:
            ev = self.poll(timeout)
            if ev is not None:
                yield ev

    def peer_rtt_ms(self, peer: int) -> int:
        return _lib.nl_peer_rtt_ms(self._handle, peer)

    def peer_count(self) -> int:
        return _lib.nl_peer_count(self._handle)

    def peer_stats(self, peer: int) -> Optional[PeerStats]:
        """Snapshot of per-peer counters/RTT estimates, or None if unknown."""
        raw = _PeerStats()
        if not _lib.nl_peer_stats(self._handle, peer, ctypes.byref(raw)):
            return None
        return PeerStats(
            packets_sent=raw.packets_sent,
            packets_received=raw.packets_received,
            bytes_sent=raw.bytes_sent,
            bytes_received=raw.bytes_received,
            retransmits=raw.retransmits,
            duplicates_received=raw.duplicates_received,
            rtt_ms=raw.rtt_ms,
            rtt_var_ms=raw.rtt_var_ms,
            rto_ms=raw.rto_ms,
        )

    def peer_capabilities(self, peer: int) -> Optional[int]:
        """Negotiated NL_CAP_* bitmask with this peer, or None if unknown."""
        caps = ctypes.c_uint32(0)
        if not _lib.nl_peer_capabilities(self._handle, peer, ctypes.byref(caps)):
            return None
        return caps.value

    def close(self) -> None:
        if self._handle:
            _lib.nl_endpoint_destroy(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class Server(Endpoint):
    def __init__(self, host: str, port: int, config: Optional[Config] = None):
        super().__init__()
        config = config or Config()
        addr = _make_address(host, port, config.family)
        raw_cfg = config._to_raw()
        handle = ctypes.c_void_p()
        _check(_lib.nl_server_create(ctypes.byref(addr), ctypes.byref(raw_cfg), ctypes.byref(handle)))
        self._handle = handle

    def enable_discovery(self, discovery_port: int) -> None:
        _check(_lib.nl_discovery_enable(self._handle, discovery_port))


class Client(Endpoint):
    def __init__(self, config: Optional[Config] = None):
        super().__init__()
        config = config or Config()
        raw_cfg = config._to_raw()
        handle = ctypes.c_void_p()
        _check(_lib.nl_client_create(ctypes.byref(raw_cfg), ctypes.byref(handle)))
        self._handle = handle

    def connect(self, host: str, port: int, family: AddressFamily = AddressFamily.UNSPEC) -> int:
        addr = _make_address(host, port, family)
        peer = ctypes.c_uint64()
        _check(_lib.nl_connect(self._handle, ctypes.byref(addr), ctypes.byref(peer)))
        return peer.value

    def probe_lan(self, discovery_port: int, timeout: float = 1.0) -> None:
        _check(_lib.nl_discovery_probe(self._handle, discovery_port, int(timeout * 1000)))

    def wait_connected(self, timeout: float = 5.0) -> Event:
        """Block until CONNECTED or CONNECT_FAILED, or raise TimeoutError."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ev = self.poll(0.1)
            if ev and ev.type in (EventType.CONNECTED, EventType.CONNECT_FAILED):
                return ev
        raise TimeoutError("timed out waiting to connect")
