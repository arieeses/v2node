package obfs

import (
	"net"
	"strings"
)

// NewServerConn wraps an accepted connection with server-side simple-obfs
// de-obfuscation for the given mode ("tls" or "http"). The returned net.Conn
// yields the plain inner stream (reads de-obfuscate, writes re-obfuscate).
//
// This is the inline form of the port-owning obfs front: protocols that
// terminate their own listener (e.g. shadowaead with an extended cipher) call
// this on each accepted conn instead of running a separate front + loopback.
// An unknown/empty mode defaults to tls.
func NewServerConn(conn net.Conn, mode string) net.Conn {
	m := modeTLS
	if strings.EqualFold(strings.TrimSpace(mode), "http") {
		m = modeHTTP
	}
	return newObfsConn(conn, m)
}
