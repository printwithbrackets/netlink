"""
Tests for the netlink Python bindings. Runs a real server and client, both
through the ctypes bindings, talking over actual loopback UDP sockets --
this is the same wire protocol a C, Go, or Rust peer would use.

Run with: NETLINK_LIBRARY_PATH=/path/to/libnetlink.so pytest test_python_bindings.py
(or just `pytest` if libnetlink.so is discoverable at the default build path).
"""
import ctypes
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import netlink

PORT_COUNTER = [34900]


def next_port():
    PORT_COUNTER[0] += 1
    return PORT_COUNTER[0]


def wait_for(client_or_server, event_type, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ev = client_or_server.poll(timeout=0.1)
        if ev and ev.type == event_type:
            return ev
    raise TimeoutError(f"timed out waiting for {event_type}")


def test_version_matches_package():
    assert netlink.__version__ == "1.1.1"
    assert netlink.version() == netlink.__version__


def test_abi_struct_sizes_match_c():
    """The ctypes mirrors below are hand-written copies of the C structs
    (the C header can't be included from Python). If C grows a field and the
    mirror doesn't, both sides still compile and the mismatch only shows up
    as memory corruption -- which is exactly what happened in 1.0.0, where
    three nl_config_t fields were missing from this mirror and
    nl_config_default wrote past the end of it.

    The C side now has _Static_asserts on the same numbers (NL_ABI_ASSERT in
    include/netlink.h); these are the mirror side of that guard.
    """
    # Mirrored 64-bit ABI sizes; see NL_ABI_ASSERT in include/netlink.h.
    expected = {
        "_Config": 56,
        "_Event": 192,
        "_PeerStats": 64,
        "_Address": 72,
    }
    for name, size in expected.items():
        actual = ctypes.sizeof(getattr(netlink, name))
        assert actual == size, (
            f"{name} mirror is {actual} bytes, C expects {size} -- the C struct "
            "gained/lost a field and this mirror wasn't updated"
        )


def test_config_default_matches_c_defaults():
    """Belt and braces for the ABI guard: if the mirror's field ORDER drifted
    from C's, the sizes could still agree while nl_config_default wrote the
    right values into the wrong offsets. Reading the defaults back through
    the mirror catches that too.
    """
    cfg = netlink._Config()
    netlink._lib.nl_config_default(ctypes.byref(cfg))
    assert cfg.transport == netlink.Transport.UDP
    assert cfg.channel_count == 4
    assert cfg.max_connections == 64
    assert cfg.connection_timeout_ms == 10000
    assert cfg.keepalive_interval_ms == 1000
    assert cfg.encryption_enabled is True
    # The v2 fields, whose absence was the 1.0.0 bug: they must exist AND
    # land on distinct nonzero-capable offsets.
    assert cfg.max_send_bytes_per_sec == 0
    assert cfg.recv_window_bytes == 32768


def test_connect_and_echo():
    port = next_port()
    server = netlink.Server("127.0.0.1", port)
    client = netlink.Client()
    try:
        peer = client.connect("127.0.0.1", port)
        client_ev = wait_for(client, netlink.EventType.CONNECTED)
        assert client_ev.peer == peer

        server_ev = wait_for(server, netlink.EventType.CONNECTED)
        server_peer = server_ev.peer

        client.send(peer, channel=0, data=b"hello world", delivery=netlink.Delivery.RELIABLE_ORDERED)
        data_ev = wait_for(server, netlink.EventType.DATA)
        assert data_ev.data == b"hello world"
        assert data_ev.channel == 0

        server.send(server_peer, channel=0, data=b"hi back", delivery=netlink.Delivery.RELIABLE_ORDERED)
        reply_ev = wait_for(client, netlink.EventType.DATA)
        assert reply_ev.data == b"hi back"
    finally:
        client.close()
        server.close()


def test_all_delivery_modes():
    port = next_port()
    server = netlink.Server("127.0.0.1", port)
    client = netlink.Client()
    try:
        peer = client.connect("127.0.0.1", port)
        wait_for(client, netlink.EventType.CONNECTED)
        wait_for(server, netlink.EventType.CONNECTED)

        modes = [
            netlink.Delivery.UNRELIABLE,
            netlink.Delivery.UNRELIABLE_SEQUENCED,
            netlink.Delivery.RELIABLE_UNORDERED,
            netlink.Delivery.RELIABLE_ORDERED,
        ]
        for i, mode in enumerate(modes):
            payload = f"mode-{i}".encode()
            client.send(peer, channel=i, data=payload, delivery=mode)
            ev = wait_for(server, netlink.EventType.DATA)
            assert ev.channel == i
            assert ev.data == payload
    finally:
        client.close()
        server.close()


def test_fragmentation_large_message():
    port = next_port()
    server = netlink.Server("127.0.0.1", port)
    client = netlink.Client()
    try:
        peer = client.connect("127.0.0.1", port)
        wait_for(client, netlink.EventType.CONNECTED)
        wait_for(server, netlink.EventType.CONNECTED)

        big = bytes((i * 37 + 3) % 256 for i in range(5000))
        client.send(peer, channel=0, data=big, delivery=netlink.Delivery.RELIABLE_ORDERED)
        ev = wait_for(server, netlink.EventType.DATA, timeout=5.0)
        assert ev.data == big
    finally:
        client.close()
        server.close()


def test_disconnect():
    port = next_port()
    server = netlink.Server("127.0.0.1", port)
    client = netlink.Client()
    try:
        peer = client.connect("127.0.0.1", port)
        wait_for(client, netlink.EventType.CONNECTED)
        wait_for(server, netlink.EventType.CONNECTED)

        client.disconnect(peer)
        ev = wait_for(server, netlink.EventType.DISCONNECTED)
        assert ev.disconnect_reason == 0  # NL_OK: graceful
    finally:
        client.close()
        server.close()


def test_server_full_denies_connection():
    port = next_port()
    server = netlink.Server("127.0.0.1", port, netlink.Config(max_connections=1))
    c1 = netlink.Client()
    c2 = netlink.Client()
    try:
        p1 = c1.connect("127.0.0.1", port)
        wait_for(c1, netlink.EventType.CONNECTED)
        wait_for(server, netlink.EventType.CONNECTED)

        c2.connect("127.0.0.1", port)
        ev = wait_for(c2, netlink.EventType.CONNECT_FAILED)
        assert ev.disconnect_reason != 0
    finally:
        c1.close()
        c2.close()
        server.close()


def test_send_ex_priority_and_peer_stats():
    port = next_port()
    server = netlink.Server("127.0.0.1", port)
    client = netlink.Client()
    try:
        peer = client.connect("127.0.0.1", port)
        wait_for(client, netlink.EventType.CONNECTED)
        server_ev = wait_for(server, netlink.EventType.CONNECTED)

        client.send_ex(peer, channel=0, data=b"urgent",
                       delivery=netlink.Delivery.RELIABLE_ORDERED,
                       priority=netlink.Priority.HIGH)
        data_ev = wait_for(server, netlink.EventType.DATA)
        assert data_ev.data == b"urgent"

        stats = client.peer_stats(peer)
        assert stats is not None
        assert stats.packets_sent >= 1
        assert isinstance(stats.rtt_ms, int)

        # Wait for at least one DATA so the ack path has run, then check
        # the server-side stats too (ack piggyback or standalone).
        server.send(server_ev.peer, channel=0, data=b"ack-me",
                    delivery=netlink.Delivery.RELIABLE_ORDERED)
        wait_for(client, netlink.EventType.DATA)
        sstats = server.peer_stats(server_ev.peer)
        assert sstats is not None
        assert sstats.packets_received >= 1

        caps = client.peer_capabilities(peer)
        assert caps is not None
        assert caps & netlink.CapFlowControl  # always negotiated on

        assert client.peer_stats(peer + 999) is None
        assert client.peer_capabilities(peer + 999) is None
    finally:
        client.close()
        server.close()


def test_peer_rtt_ms_and_peer_count():
    port = next_port()
    server = netlink.Server("127.0.0.1", port)
    client = netlink.Client()
    try:
        assert client.peer_count() == 0
        assert server.peer_count() == 0
        assert client.peer_rtt_ms(1) == 0  # unknown peer

        peer = client.connect("127.0.0.1", port)
        wait_for(client, netlink.EventType.CONNECTED)
        server_ev = wait_for(server, netlink.EventType.CONNECTED)
        assert client.peer_count() == 1
        assert server.peer_count() == 1

        # Force a reliable round trip so an RTT sample lands.
        client.send(peer, channel=0, data=b"rtt probe",
                    delivery=netlink.Delivery.RELIABLE_ORDERED)
        wait_for(server, netlink.EventType.DATA)
        server.send(server_ev.peer, channel=0, data=b"rtt pong",
                    delivery=netlink.Delivery.RELIABLE_ORDERED)
        wait_for(client, netlink.EventType.DATA)

        rtt = client.peer_rtt_ms(peer)
        assert isinstance(rtt, int)
        assert rtt < 2000
        assert client.peer_rtt_ms(peer + 999) == 0
    finally:
        client.close()
        server.close()


def test_error_string_available():
    # NetLinkError goes through nl_error_string; force a failure path
    # (duplicate connect -> NL_ERR_ALREADY_CONNECTED) without requiring pytest.
    port = next_port()
    server = netlink.Server("127.0.0.1", port)
    client = netlink.Client()
    try:
        client.connect("127.0.0.1", port)
        try:
            client.connect("127.0.0.1", port)
            raise AssertionError("second connect should have raised")
        except netlink.NetLinkError as e:
            assert e.code == -6  # NL_ERR_ALREADY_CONNECTED
            assert "already connected" in str(e)
    finally:
        client.close()
        server.close()


if __name__ == "__main__":
    # Self-contained runner: discovers test_* functions and runs them
    # without requiring pytest (which may not be installed).
    import traceback

    failures = 0
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        try:
            fn()
            print(f"  OK   {name}")
        except Exception:
            failures += 1
            print(f"  FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests)} run, {failures} failed")
    sys.exit(1 if failures else 0)
