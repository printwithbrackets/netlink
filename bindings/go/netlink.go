// Package netlink provides Go bindings for the NetLink C library via cgo.
//
// IMPORTANT: unlike the Python bindings in this repository (which were
// built and tested against the real compiled library as part of this
// project), this Go binding could not be compiled or run in the
// environment that produced it -- no Go toolchain was available. It is
// written carefully against the same stable C ABI (include/netlink.h)
// that the Python bindings were verified against byte-for-byte, and the
// cgo patterns used here are standard, but you should treat it as
// needing its first real build/test pass, not as pre-verified the way
// the C core and Python bindings are. Please file an issue (or better, a
// PR with `go build`/`go vet` output) if something doesn't line up.
//
// Build requirements: the netlink C library must be built first (`make`
// in the repository root produces build/libnetlink.a / .so), and its
// headers must be reachable from the cgo preamble below -- adjust the
// CFLAGS/LDFLAGS paths for your setup, or use pkg-config once a .pc file
// is added (see the roadmap in the top-level README).
package netlink

/*
#cgo CFLAGS: -I${SRCDIR}/../../include
#cgo LDFLAGS: -L${SRCDIR}/../../build -lnetlink -lcrypto -lpthread
#include <stdlib.h>
#include <string.h>
#include "netlink.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

// Delivery mirrors nl_delivery_t.
type Delivery int

const (
	Unreliable           Delivery = 0
	UnreliableSequenced  Delivery = 1
	ReliableUnordered    Delivery = 2
	ReliableOrdered      Delivery = 3
)

// EventType mirrors nl_event_type_t.
type EventType int

const (
	EventNone           EventType = 0
	EventConnected      EventType = 1
	EventDisconnected   EventType = 2
	EventData           EventType = 3
	EventConnectFailed  EventType = 4
	EventDiscoveryReply EventType = 5
)

// AddressFamily mirrors nl_af_t.
type AddressFamily int

const (
	AFUnspec AddressFamily = 0
	AFInet   AddressFamily = 4
	AFInet6  AddressFamily = 6
)

// Priority constants mirror NL_PRIORITY_* (nl_send_ex).
const (
	PriorityLow      uint8 = 0
	PriorityNormal   uint8 = 64
	PriorityHigh     uint8 = 128
	PriorityCritical uint8 = 192
)

// Capability bits mirror NL_CAP_*.
const (
	CapFlowControl uint32 = 0x00000001
	CapPriority    uint32 = 0x00000002
	CapRateLimit   uint32 = 0x00000004
)

// PeerStats mirrors nl_peer_stats_t.
type PeerStats struct {
	PacketsSent         uint64
	PacketsReceived     uint64
	BytesSent           uint64
	BytesReceived       uint64
	Retransmits         uint64
	DuplicatesReceived  uint64
	RTTMs               uint32
	RTTVarMs            uint32
	RtoMs               uint32
}

// PeerID mirrors nl_peer_id_t (a uint64 connection identifier).
type PeerID uint64

// Error wraps an nl_result_t.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("netlink: %s (code %d)", e.Message, e.Code) }

func newError(code C.nl_result_t) error {
	if code == C.NL_OK {
		return nil
	}
	msg := C.GoString(C.nl_error_string(code))
	return &Error{Code: int(code), Message: msg}
}

// Config mirrors nl_config_t, with Go-friendly defaults via NewConfig.
type Config struct {
	ChannelCount        uint8
	MaxConnections      uint32
	ConnectionTimeoutMs uint32
	KeepaliveIntervalMs uint32
	EncryptionEnabled   bool
	ServerName          string
	Family              AddressFamily
}

// NewConfig returns a Config populated with the library's defaults
// (4 channels, 64 max connections, 10s timeout, 1s keepalive, encryption on).
func NewConfig() Config {
	var raw C.nl_config_t
	C.nl_config_default(&raw)
	return Config{
		ChannelCount:        uint8(raw.channel_count),
		MaxConnections:      uint32(raw.max_connections),
		ConnectionTimeoutMs: uint32(raw.connection_timeout_ms),
		KeepaliveIntervalMs: uint32(raw.keepalive_interval_ms),
		EncryptionEnabled:   bool(raw.encryption_enabled),
		Family:              AFUnspec,
	}
}

func (c Config) toC() (C.nl_config_t, *C.char) {
	var raw C.nl_config_t
	C.nl_config_default(&raw)
	raw.channel_count = C.uint8_t(c.ChannelCount)
	raw.max_connections = C.uint32_t(c.MaxConnections)
	raw.connection_timeout_ms = C.uint32_t(c.ConnectionTimeoutMs)
	raw.keepalive_interval_ms = C.uint32_t(c.KeepaliveIntervalMs)
	raw.encryption_enabled = C.bool(c.EncryptionEnabled)
	raw.family = C.nl_af_t(c.Family)
	var nameCStr *C.char
	if c.ServerName != "" {
		nameCStr = C.CString(c.ServerName) // caller must free after nl_server_create returns
		raw.server_name = nameCStr
	}
	return raw, nameCStr
}

func addressToC(host string, port uint16, family AddressFamily) (C.nl_address_t, *C.char) {
	var addr C.nl_address_t
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))
	// nl_address_t.host is a fixed-size char[64] array, not a pointer --
	// copy into it directly rather than assigning a pointer.
	C.strncpy((*C.char)(unsafe.Pointer(&addr.host[0])), cHost, C.size_t(len(addr.host)-1))
	addr.port = C.uint16_t(port)
	addr.family = C.nl_af_t(family)
	return addr, nil
}

// Event mirrors nl_event_t, with `Data` copied into a Go-owned []byte
// (the underlying C buffer is only valid until the next PollEvent call,
// so we copy it here rather than expose the raw pointer).
type Event struct {
	Type               EventType
	Peer               PeerID
	Channel            uint8
	Data               []byte
	DisconnectReason   error
	FromHost           string
	FromPort           uint16
	ServerName         string
	ServerPlayerCount  uint32
	ServerMaxPlayers   uint32
}

func eventFromC(raw *C.nl_event_t) Event {
	ev := Event{
		Type:              EventType(raw.event_type),
		Peer:              PeerID(raw.peer),
		Channel:           uint8(raw.channel),
		FromHost:          C.GoString((*C.char)(unsafe.Pointer(&raw.from_address.host[0]))),
		FromPort:          uint16(raw.from_address.port),
		ServerName:        C.GoString((*C.char)(unsafe.Pointer(&raw.server_name[0]))),
		ServerPlayerCount: uint32(raw.server_player_count),
		ServerMaxPlayers:  uint32(raw.server_max_players),
	}
	if raw.disconnect_reason != C.NL_OK {
		ev.DisconnectReason = newError(raw.disconnect_reason)
	}
	if raw.data != nil && raw.data_len > 0 {
		ev.Data = C.GoBytes(unsafe.Pointer(raw.data), C.int(raw.data_len))
	}
	return ev
}

// Endpoint wraps a *C.nl_endpoint_t; embedded in Server and Client.
type Endpoint struct {
	handle *C.nl_endpoint_t
}

// Send encodes and enqueues data for delivery to peer on the given
// channel, using the given delivery guarantee. Safe to call from any
// goroutine.
func (e *Endpoint) Send(peer PeerID, channel uint8, delivery Delivery, data []byte) error {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	res := C.nl_send(e.handle, C.nl_peer_id_t(peer), C.uint8_t(channel), C.nl_delivery_t(delivery), ptr, C.size_t(len(data)))
	return newError(res)
}

// SendEx is like Send with an explicit priority (0..255; see
// PriorityNormal etc.). When the send window is closed, higher-priority
// messages flush first as budget opens.
func (e *Endpoint) SendEx(peer PeerID, channel uint8, delivery Delivery, data []byte, priority uint8) error {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	res := C.nl_send_ex(e.handle, C.nl_peer_id_t(peer), C.uint8_t(channel), C.nl_delivery_t(delivery), ptr, C.size_t(len(data)), C.uint8_t(priority))
	return newError(res)
}

// PollEvent waits up to timeout for the next event. A negative timeout
// blocks forever; zero returns immediately if nothing is queued.
func (e *Endpoint) PollEvent(timeout time.Duration) (Event, bool) {
	var raw C.nl_event_t
	ms := C.int(-1)
	if timeout >= 0 {
		ms = C.int(timeout.Milliseconds())
	}
	ok := C.nl_poll_event(e.handle, &raw, ms)
	if !bool(ok) {
		return Event{}, false
	}
	return eventFromC(&raw), true
}

// Disconnect gracefully closes a connection.
func (e *Endpoint) Disconnect(peer PeerID) error {
	return newError(C.nl_disconnect(e.handle, C.nl_peer_id_t(peer)))
}

// PeerRTTMillis returns the current smoothed round-trip-time estimate.
func (e *Endpoint) PeerRTTMillis(peer PeerID) uint32 {
	return uint32(C.nl_peer_rtt_ms(e.handle, C.nl_peer_id_t(peer)))
}

// PeerCount returns the number of currently-established connections.
func (e *Endpoint) PeerCount() uint32 {
	return uint32(C.nl_peer_count(e.handle))
}

// PeerStats returns a snapshot of per-peer counters and RTT estimates.
// The second result is false if peer is not a known connection.
func (e *Endpoint) PeerStats(peer PeerID) (PeerStats, bool) {
	var raw C.nl_peer_stats_t
	ok := C.nl_peer_stats(e.handle, C.nl_peer_id_t(peer), &raw)
	if !bool(ok) {
		return PeerStats{}, false
	}
	return PeerStats{
		PacketsSent:        uint64(raw.packets_sent),
		PacketsReceived:    uint64(raw.packets_received),
		BytesSent:          uint64(raw.bytes_sent),
		BytesReceived:      uint64(raw.bytes_received),
		Retransmits:        uint64(raw.retransmits),
		DuplicatesReceived: uint64(raw.duplicates_received),
		RTTMs:              uint32(raw.rtt_ms),
		RTTVarMs:           uint32(raw.rtt_var_ms),
		RtoMs:              uint32(raw.rto_ms),
	}, true
}

// PeerCapabilities returns the NL_CAP_* bits negotiated with peer during
// the handshake. The second result is false if peer is unknown.
func (e *Endpoint) PeerCapabilities(peer PeerID) (uint32, bool) {
	var caps C.uint32_t
	ok := C.nl_peer_capabilities(e.handle, C.nl_peer_id_t(peer), &caps)
	return uint32(caps), bool(ok)
}

// Close shuts down the endpoint's background threads and frees all
// associated resources. The Endpoint must not be used afterwards.
func (e *Endpoint) Close() {
	if e.handle != nil {
		C.nl_endpoint_destroy(e.handle)
		e.handle = nil
	}
}

// Server accepts incoming connections.
type Server struct {
	Endpoint
}

// NewServer binds a UDP socket at host:port and starts accepting
// connections in a background thread.
func NewServer(host string, port uint16, cfg Config) (*Server, error) {
	addr, _ := addressToC(host, port, cfg.Family)
	cCfg, nameCStr := cfg.toC()
	if nameCStr != nil {
		defer C.free(unsafe.Pointer(nameCStr))
	}

	var handle *C.nl_endpoint_t
	res := C.nl_server_create(&addr, &cCfg, &handle)
	if err := newError(res); err != nil {
		return nil, err
	}
	return &Server{Endpoint{handle: handle}}, nil
}

// EnableDiscovery starts responding to LAN discovery broadcasts on the
// given port.
func (s *Server) EnableDiscovery(discoveryPort uint16) error {
	return newError(C.nl_discovery_enable(s.handle, C.uint16_t(discoveryPort)))
}

// Client initiates outbound connections.
type Client struct {
	Endpoint
}

// NewClient creates a client endpoint (not yet connected to anything).
func NewClient(cfg Config) (*Client, error) {
	cCfg, nameCStr := cfg.toC()
	if nameCStr != nil {
		defer C.free(unsafe.Pointer(nameCStr))
	}
	var handle *C.nl_endpoint_t
	res := C.nl_client_create(&cCfg, &handle)
	if err := newError(res); err != nil {
		return nil, err
	}
	return &Client{Endpoint{handle: handle}}, nil
}

// Connect begins connecting to server_addr. It returns immediately with
// the peer id that will be used for this connection once established;
// wait for an EventConnected (or EventConnectFailed) via PollEvent.
func (c *Client) Connect(host string, port uint16) (PeerID, error) {
	addr, _ := addressToC(host, port, AFUnspec)
	var peer C.nl_peer_id_t
	res := C.nl_connect(c.handle, &addr, &peer)
	if err := newError(res); err != nil {
		return 0, err
	}
	return PeerID(peer), nil
}

// ProbeLAN broadcasts a discovery probe; replies arrive as
// EventDiscoveryReply events over subsequent PollEvent calls.
func (c *Client) ProbeLAN(discoveryPort uint16, timeout time.Duration) error {
	return newError(C.nl_discovery_probe(c.handle, C.uint16_t(discoveryPort), C.int(timeout.Milliseconds())))
}

// WaitConnected blocks (polling internally) until the connection succeeds
// or fails, or the timeout elapses.
func (c *Client) WaitConnected(timeout time.Duration) (Event, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ev, ok := c.PollEvent(100 * time.Millisecond)
		if ok && (ev.Type == EventConnected || ev.Type == EventConnectFailed) {
			return ev, nil
		}
	}
	return Event{}, errors.New("netlink: timed out waiting to connect")
}
