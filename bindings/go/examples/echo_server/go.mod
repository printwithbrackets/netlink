module echo_server

go 1.21

require github.com/yourusername/netlink/bindings/go v0.0.0

// Points back at the bindings package in this repository rather than
// resolving the (placeholder) GitHub path over the network -- this is
// the standard way to build a local, unpublished Go module against a
// sibling module during development.
replace github.com/yourusername/netlink/bindings/go => ../..
