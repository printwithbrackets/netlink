// Package-level integration tests for the Go bindings: real Server +
// Client over loopback UDP, speaking the same wire protocol as the C core.
//
// Requires the C library to be built first (make at the repository root
// produces build/libnetlink.a). Run with:
//
//	cd bindings/go && go test ./...
package netlink

import (
	"bytes"
	"testing"
	"time"
)

// uniquePort returns a distinct port per test to avoid collisions when
// tests run sequentially on the same machine.
var portBase = uint16(36100)

func uniquePort() uint16 {
	portBase++
	return portBase
}

// waitEvent polls until an event of the given type arrives (or fails the test).
func waitEvent(t *testing.T, ep *Endpoint, typ EventType, timeout time.Duration) Event {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ev, ok := ep.PollEvent(50 * time.Millisecond)
		if !ok {
			continue
		}
		if ev.Type == typ {
			return ev
		}
	}
	t.Fatalf("timed out waiting for event type %d", typ)
	return Event{}
}

// connectedPair spins up a server and client, connects them, and waits
// for CONNECTED on both sides. Returns (server, client, clientPeer,
// serverPeer). Callers must Close both.
func connectedPair(t *testing.T) (*Server, *Client, PeerID, PeerID) {
	t.Helper()
	port := uniquePort()

	server, err := NewServer("127.0.0.1", port, NewConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	client, err := NewClient(NewConfig())
	if err != nil {
		server.Close()
		t.Fatalf("NewClient: %v", err)
	}

	clientPeer, err := client.Connect("127.0.0.1", port)
	if err != nil {
		server.Close()
		client.Close()
		t.Fatalf("Connect: %v", err)
	}

	waitEvent(t, &client.Endpoint, EventConnected, 3*time.Second)
	serverEv := waitEvent(t, &server.Endpoint, EventConnected, 3*time.Second)
	return server, client, clientPeer, serverEv.Peer
}

func TestNewConfigDefaults(t *testing.T) {
	cfg := NewConfig()
	if cfg.ChannelCount != 4 {
		t.Errorf("ChannelCount = %d, want 4", cfg.ChannelCount)
	}
	if cfg.MaxConnections != 64 {
		t.Errorf("MaxConnections = %d, want 64", cfg.MaxConnections)
	}
	if cfg.ConnectionTimeoutMs != 10000 {
		t.Errorf("ConnectionTimeoutMs = %d, want 10000", cfg.ConnectionTimeoutMs)
	}
	if cfg.KeepaliveIntervalMs != 1000 {
		t.Errorf("KeepaliveIntervalMs = %d, want 1000", cfg.KeepaliveIntervalMs)
	}
	if !cfg.EncryptionEnabled {
		t.Error("EncryptionEnabled = false, want true")
	}
}

func TestConnectAndEcho(t *testing.T) {
	server, client, clientPeer, serverPeer := connectedPair(t)
	defer server.Close()
	defer client.Close()

	msg := []byte("hello from go")
	if err := client.Send(clientPeer, 0, ReliableOrdered, msg); err != nil {
		t.Fatalf("client.Send: %v", err)
	}

	dataEv := waitEvent(t, &server.Endpoint, EventData, 3*time.Second)
	if dataEv.Peer != serverPeer {
		t.Errorf("server saw peer %d, want %d", dataEv.Peer, serverPeer)
	}
	if dataEv.Channel != 0 {
		t.Errorf("channel = %d, want 0", dataEv.Channel)
	}
	if !bytes.Equal(dataEv.Data, msg) {
		t.Errorf("data = %q, want %q", dataEv.Data, msg)
	}

	reply := []byte("hi from go server")
	if err := server.Send(serverPeer, 0, ReliableOrdered, reply); err != nil {
		t.Fatalf("server.Send: %v", err)
	}
	clientEv := waitEvent(t, &client.Endpoint, EventData, 3*time.Second)
	if !bytes.Equal(clientEv.Data, reply) {
		t.Errorf("client saw %q, want %q", clientEv.Data, reply)
	}
}

func TestAllDeliveryModes(t *testing.T) {
	server, client, clientPeer, _ := connectedPair(t)
	defer server.Close()
	defer client.Close()

	modes := []Delivery{Unreliable, UnreliableSequenced, ReliableUnordered, ReliableOrdered}
	for i, mode := range modes {
		payload := []byte{byte('a' + i)}
		if err := client.Send(clientPeer, uint8(i), mode, payload); err != nil {
			t.Fatalf("Send mode %d: %v", i, err)
		}
		ev := waitEvent(t, &server.Endpoint, EventData, 3*time.Second)
		if ev.Channel != uint8(i) {
			t.Errorf("channel = %d, want %d", ev.Channel, i)
		}
		if !bytes.Equal(ev.Data, payload) {
			t.Errorf("mode %d payload = %q, want %q", i, ev.Data, payload)
		}
	}
}

func TestFragmentationLargeMessage(t *testing.T) {
	server, client, clientPeer, _ := connectedPair(t)
	defer server.Close()
	defer client.Close()

	big := make([]byte, 5000)
	for i := range big {
		big[i] = byte((i*37 + 3) % 256)
	}
	if err := client.Send(clientPeer, 0, ReliableOrdered, big); err != nil {
		t.Fatalf("Send: %v", err)
	}
	ev := waitEvent(t, &server.Endpoint, EventData, 5*time.Second)
	if !bytes.Equal(ev.Data, big) {
		t.Errorf("large message mismatch: got %d bytes, want %d", len(ev.Data), len(big))
	}
}

func TestSendExPriorityAndPeerStats(t *testing.T) {
	server, client, clientPeer, serverPeer := connectedPair(t)
	defer server.Close()
	defer client.Close()

	if err := client.SendEx(clientPeer, 0, ReliableOrdered, []byte("urgent"), PriorityHigh); err != nil {
		t.Fatalf("SendEx: %v", err)
	}
	ev := waitEvent(t, &server.Endpoint, EventData, 3*time.Second)
	if string(ev.Data) != "urgent" {
		t.Errorf("data = %q, want urgent", ev.Data)
	}

	stats, ok := client.PeerStats(clientPeer)
	if !ok {
		t.Fatal("PeerStats returned false for known peer")
	}
	if stats.PacketsSent < 1 {
		t.Errorf("PacketsSent = %d, want >= 1", stats.PacketsSent)
	}
	if stats.RTTMs > 2000 {
		t.Errorf("RTTMs = %d, want < 2000", stats.RTTMs)
	}

	// Unknown peer returns false.
	if _, ok := client.PeerStats(clientPeer + 999); ok {
		t.Error("PeerStats for unknown peer returned true")
	}

	caps, ok := client.PeerCapabilities(clientPeer)
	if !ok {
		t.Fatal("PeerCapabilities returned false for known peer")
	}
	if caps&CapFlowControl == 0 {
		t.Errorf("caps = %#x, missing CapFlowControl", caps)
	}
	if _, ok := client.PeerCapabilities(clientPeer + 999); ok {
		t.Error("PeerCapabilities for unknown peer returned true")
	}

	// Server-side stats after a reverse send.
	if err := server.Send(serverPeer, 0, ReliableOrdered, []byte("ack-me")); err != nil {
		t.Fatalf("server.Send: %v", err)
	}
	waitEvent(t, &client.Endpoint, EventData, 3*time.Second)
	sstats, ok := server.PeerStats(serverPeer)
	if !ok {
		t.Fatal("server PeerStats returned false for known peer")
	}
	if sstats.PacketsReceived < 1 {
		t.Errorf("server PacketsReceived = %d, want >= 1", sstats.PacketsReceived)
	}
}

func TestPeerCountAndRTT(t *testing.T) {
	server, client, clientPeer, _ := connectedPair(t)
	defer server.Close()
	defer client.Close()

	if n := client.PeerCount(); n != 1 {
		t.Errorf("client PeerCount = %d, want 1", n)
	}
	if n := server.PeerCount(); n != 1 {
		t.Errorf("server PeerCount = %d, want 1", n)
	}

	// Unknown peer RTT is 0.
	if rtt := client.PeerRTTMillis(clientPeer + 999); rtt != 0 {
		t.Errorf("unknown peer RTT = %d, want 0", rtt)
	}

	// Force a reliable round trip so an RTT sample lands.
	if err := client.Send(clientPeer, 0, ReliableOrdered, []byte("ping")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	serverEv := waitEvent(t, &server.Endpoint, EventData, 3*time.Second)
	if err := server.Send(serverEv.Peer, 0, ReliableOrdered, []byte("pong")); err != nil {
		t.Fatalf("server.Send: %v", err)
	}
	waitEvent(t, &client.Endpoint, EventData, 3*time.Second)

	if rtt := client.PeerRTTMillis(clientPeer); rtt >= 2000 {
		t.Errorf("RTT = %d, want < 2000", rtt)
	}
}

func TestDisconnect(t *testing.T) {
	server, client, clientPeer, _ := connectedPair(t)
	defer server.Close()
	defer client.Close()

	if err := client.Disconnect(clientPeer); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	ev := waitEvent(t, &server.Endpoint, EventDisconnected, 3*time.Second)
	if ev.DisconnectReason != nil {
		t.Errorf("DisconnectReason = %v, want nil (graceful)", ev.DisconnectReason)
	}
}

func TestServerFullDeniesConnection(t *testing.T) {
	port := uniquePort()
	cfg := NewConfig()
	cfg.MaxConnections = 1
	server, err := NewServer("127.0.0.1", port, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.Close()

	c1, err := NewClient(NewConfig())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c1.Close()
	c2, err := NewClient(NewConfig())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c2.Close()

	if _, err := c1.Connect("127.0.0.1", port); err != nil {
		t.Fatalf("c1 Connect: %v", err)
	}
	waitEvent(t, &c1.Endpoint, EventConnected, 3*time.Second)
	waitEvent(t, &server.Endpoint, EventConnected, 3*time.Second)

	if _, err := c2.Connect("127.0.0.1", port); err != nil {
		t.Fatalf("c2 Connect: %v", err)
	}
	ev := waitEvent(t, &c2.Endpoint, EventConnectFailed, 3*time.Second)
	if ev.DisconnectReason == nil {
		t.Fatal("expected non-nil DisconnectReason on connect failure")
	}
}

func TestDuplicateConnectRejected(t *testing.T) {
	port := uniquePort()
	server, err := NewServer("127.0.0.1", port, NewConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.Close()
	client, err := NewClient(NewConfig())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if _, err := client.Connect("127.0.0.1", port); err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	// Second connect while first is in flight or established.
	if _, err := client.Connect("127.0.0.1", port); err == nil {
		t.Fatal("second Connect: want error, got nil")
	} else {
		var nle *Error
		if !errorsAs(err, &nle) {
			t.Fatalf("error type = %T, want *Error", err)
		}
		if nle.Code != -6 { // NL_ERR_ALREADY_CONNECTED
			t.Errorf("Code = %d, want -6 (ALREADY_CONNECTED)", nle.Code)
		}
	}
}

func TestErrorFormatting(t *testing.T) {
	e := &Error{Code: -6, Message: "already connected"}
	s := e.Error()
	if s == "" {
		t.Error("Error() returned empty string")
	}
}

// errorsAs is a tiny local helper so we don't need Go 1.20+ errors.As
// semantics beyond pointer matching.
func errorsAs(err error, target **Error) bool {
	if e, ok := err.(*Error); ok {
		*target = e
		return true
	}
	return false
}
