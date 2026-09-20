#!/usr/bin/env python3
"""
echo_client.py - connects to a NetLink echo server (the C, Go, or Rust
example server -- they all speak the same wire protocol) and prints the
echoes it gets back.

Usage:
    NETLINK_LIBRARY_PATH=../../build/libnetlink.so python3 echo_client.py [host] [port]
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netlink


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

    client = netlink.Client()
    peer = client.connect(host, port)
    print(f"Connecting to {host}:{port} ...")

    ev = client.wait_connected(timeout=5.0)
    if ev.type != netlink.EventType.CONNECTED:
        print(f"connection failed: {netlink.NetLinkError(ev.disconnect_reason)}")
        return 1
    print(f"Connected! (peer id {ev.peer})")

    client.send(peer, channel=0, data=b"hello reliable", delivery=netlink.Delivery.RELIABLE_ORDERED)
    client.send(peer, channel=1, data=b"hello sequenced", delivery=netlink.Delivery.UNRELIABLE_SEQUENCED)
    client.send(peer, channel=2, data=b"hello unordered", delivery=netlink.Delivery.RELIABLE_UNORDERED)

    received = 0
    deadline = time.monotonic() + 5.0
    while received < 3 and time.monotonic() < deadline:
        ev = client.poll(timeout=0.5)
        if ev and ev.type == netlink.EventType.DATA:
            print(f"Echo received on channel {ev.channel}: {ev.data!r}")
            received += 1
        elif ev and ev.type == netlink.EventType.DISCONNECTED:
            print(f"Disconnected: {ev.disconnect_reason}")
            break

    client.disconnect(peer)
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
