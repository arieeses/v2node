package shadowflow

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// ====================================================================
// ShadowStream Framed Transport — see SHADOWSTREAM.md for the wire spec.
//
// FramedConn wraps a net.Conn (the Reality TLS connection) and, beneath the
// proxy protocol, frames the byte stream into DATA/PAD frames. Unlike the
// byte-preserving re-chunker (ShapedBufWriter), this layer can PAD a record up
// to any target size using PAD frames that the peer strips — the capability
// required to eliminate small-record and TLS-in-TLS size fingerprints.
//
// Both ends (node + client) must implement this identically.
// ====================================================================

const (
	frameDATA byte = 0x00
	framePAD  byte = 0x01

	frameHeaderLen = 3     // Type(1) + Length(2, BE)
	maxFramePayloadV1 = 0xFFFF // Length field is uint16
)

// FramedConn is a net.Conn that speaks the ShadowStream framing.
type FramedConn struct {
	net.Conn

	profile *TrafficProfile
	dir     Direction

	// write state
	wmu     sync.Mutex
	initIdx int

	// read state
	rmu    sync.Mutex
	rleft  []byte           // decoded DATA bytes not yet returned to the caller
	hdr    [frameHeaderLen]byte
}

// NewFramedConn wraps conn. The engine supplies the per-connection profile;
// pick a random profile in dynamic/random mode so connections decorrelate.
func NewFramedConn(conn net.Conn, engine *CamouflageEngine, dir Direction) *FramedConn {
	prof := engine.getProfile()
	if engine.config != nil && (engine.config.Mode == "dynamic" || engine.config.Mode == "random") {
		if p := GetRandomProfile(); p != nil {
			prof = p
		}
	}
	return &FramedConn{Conn: conn, profile: prof, dir: dir}
}

// Write frames p into profile-sized records, padding short records with PAD
// frames, and writes each record as one Conn.Write (⇒ one TLS record).
func (c *FramedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

	off := 0
	for off < len(p) {
		target := c.nextTargetSize()
		rec := make([]byte, 0, target)

		// Fill the record with DATA frame(s) from the pending app data.
		for off < len(p) {
			space := target - len(rec) - frameHeaderLen
			if space <= 0 {
				break
			}
			n := len(p) - off
			if n > space {
				n = space
			}
			if n > maxFramePayloadV1 {
				n = maxFramePayloadV1
			}
			rec = appendFrame(rec, frameDATA, p[off:off+n])
			off += n
		}

		// Pad the record up to the target size with a PAD frame (if it fits).
		if pad := target - len(rec) - frameHeaderLen; pad >= 0 {
			padBytes := make([]byte, pad)
			if _, err := rand.Read(padBytes); err != nil {
				return off, err
			}
			rec = appendFrame(rec, framePAD, padBytes)
		}

		if _, err := c.Conn.Write(rec); err != nil {
			return off, err
		}
	}
	return off, nil
}

// Read returns the next application (DATA) bytes, transparently skipping PAD
// frames. Byte delivery is exact.
func (c *FramedConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if len(c.rleft) > 0 {
		n := copy(p, c.rleft)
		c.rleft = c.rleft[n:]
		return n, nil
	}

	for {
		if _, err := io.ReadFull(c.Conn, c.hdr[:]); err != nil {
			return 0, err
		}
		typ := c.hdr[0]
		ln := int(binary.BigEndian.Uint16(c.hdr[1:3]))
		if ln == 0 {
			continue // header-only marker
		}
		payload := make([]byte, ln)
		if _, err := io.ReadFull(c.Conn, payload); err != nil {
			return 0, err
		}
		if typ == framePAD {
			continue // cover — discard
		}
		// DATA
		n := copy(p, payload)
		if n < len(payload) {
			c.rleft = payload[n:]
		}
		return n, nil
	}
}

// nextTargetSize samples the next record size using this connection's own
// initial-sequence index (caller holds wmu).
func (c *FramedConn) nextTargetSize() int {
	prof := c.profile
	var size int
	switch c.dir {
	case C2S:
		size = SampleInitialSize(prof.C2SInitial, c.initIdx)
		if size > 0 {
			c.initIdx++
		} else {
			size = SampleSize(prof.C2SSizes)
		}
	case S2C:
		size = SampleInitialSize(prof.S2CInitial, c.initIdx)
		if size > 0 {
			c.initIdx++
		} else {
			size = SampleSize(prof.S2CSizes)
		}
	}
	if size < prof.MinRecordPayload {
		size = prof.MinRecordPayload
	}
	if size > prof.MaxRecordPayload {
		size = prof.MaxRecordPayload
	}
	// A record must hold at least one frame header.
	if size < frameHeaderLen+1 {
		size = frameHeaderLen + 1
	}
	return size
}

// appendFrame appends a Type+Length+Payload frame to dst.
func appendFrame(dst []byte, typ byte, payload []byte) []byte {
	var hdr [frameHeaderLen]byte
	hdr[0] = typ
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(payload)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, payload...)
	return dst
}
