// Package setup holds the client side of the managed Verify key setup and
// receiver configuration: the file formats ratify-keys and a receiver
// exchange with Verify, and the stateless checks on them. It is not part of
// the Protocol v2 specification or its conformance suite.
//
// Every exported symbol is listed in PUBLIC_API.txt; a test fails on any
// other. Nothing here issues challenges, stores state, or decides whether a
// request is authorized: a parse that succeeds is necessary, never
// sufficient.
package setup
