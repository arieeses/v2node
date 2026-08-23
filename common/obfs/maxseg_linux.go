//go:build linux

package obfs

import "syscall"

// setTCPMaxSeg caps the outgoing TCP segment size (TCP_MAXSEG) on fd. On mobile
// carriers the path MTU is often well under 1500 and PMTUD is black-holed
// (ICMP filtered), so full-size 1460-byte segments to the client are silently
// dropped while small ones get through — the connection stalls. Clamping the
// server's send MSS avoids emitting segments the path cannot carry.
func setTCPMaxSeg(fd, mss int) {
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}
