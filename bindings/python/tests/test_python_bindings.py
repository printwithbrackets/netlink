"""
Tests for the netlink Python bindings. Runs a real server and client, both
through the ctypes bindings, talking over actual loopback UDP sockets --
this is the same wire protocol a C, Go, or Rust peer would use.

Run with: NETLINK_LIBRARY_PATH=/path/to/libnetlink.so pytest test_python_bindings.py
(or just `pytest` if libnetlink.so is discoverable at the default build path).
"""
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
    assert netlink.__version__ == "1.0.0"
    assert netlink.version() == netlink.__version__


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


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
