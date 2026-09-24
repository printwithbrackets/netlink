module echo_server

go 1.21

require github.com/printwithbrackets/netlink/bindings/go v1.0.0

// Points back at the bindings package in this repository rather than
// resolving the GitHub path over the network -- this is the standard way
// to build a local, unpublished Go module against a sibling module during
// development.
replace github.com/printwithbrackets/netlink/bindings/go => ../..
