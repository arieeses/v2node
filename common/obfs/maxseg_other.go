//go:build !linux

package obfs

// setTCPMaxSeg is a no-op on non-Linux platforms (TCP_MAXSEG is Linux-specific).
func setTCPMaxSeg(fd, mss int) {}
