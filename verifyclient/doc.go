// Package verifyclient groups the client side of the Ratify Verify API:
// the file formats and stateless checks that customer tools share with
// Verify (setup, exportsig, feedbatch) and the customer-run IAM status
// bridge (iambridge). The commands in cmd/ratify-keys,
// cmd/ratify-reference-receiver, cmd/ratify-iam-bridge and the
// cmd/ratify-*-status-source sources are built on these packages.
//
// These packages are not part of the Protocol v2 specification or its
// conformance suite. A verifier that checks Protocol v2 proofs needs none of
// them.
//
// Compatibility: these packages are experimental until 2.0.0. Their Go API
// may change in any pre-2.0.0 release; the file formats they read and write
// are kept compatible with files already in use (testdata/v2_wire_golden.json).
//
// PUBLIC_API.txt lists every exported symbol of these packages. The
// boundary tests fail on any exported symbol that is not listed, on any
// dependency outside the standard library and the Protocol v2 module, and
// on any protocol package that imports verifyclient.
package verifyclient
