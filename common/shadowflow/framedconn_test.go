package shadowflow

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// countConn counts bytes written to the underlying conn.
type countConn struct {
	net.Conn
	mu      sync.Mutex
	written int
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.written += n
	c.mu.Unlock()
	return n, err
}

func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*37 + 11)
	}
	return b
}

// TestFramedConnRoundTrip proves byte-exact delivery through the framing layer
// (DATA reassembled, PAD stripped) across sizes that stress the padding path.
func TestFramedConnRoundTrip(t *testing.T) {
	eng := NewCamouflageEngine(&CamouflageConfig{Profile: testProfile(), Mode: ""})

	for _, n := range []int{1, 5, 25, 26, 100, 1000, 8192, 16384, 50000, 200000} {
		a, b := net.Pipe()
		client := NewFramedConn(a, eng, C2S)
		server := NewFramedConn(b, eng, S2C)

		in := patternBytes(n)
		errCh := make(chan error, 1)
		go func() {
			_, err := client.Write(in)
			// Close the write side so the reader drains the trailing PAD frame
			// and then sees EOF. (net.Pipe is fully synchronous: the reader MUST
			// consume every wire byte, including padding, for Write to complete.)
			a.Close()
			errCh <- err
		}()

		// Read until EOF so trailing PAD frames are drained.
		got := make([]byte, 0, n)
		buf := make([]byte, 4096)
		for {
			m, err := server.Read(buf)
			if m > 0 {
				got = append(got, buf[:m]...)
			}
			if err != nil {
				break
			}
		}
		if werr := <-errCh; werr != nil {
			t.Fatalf("size %d: write error %v", n, werr)
		}
		b.Close()

		if !bytes.Equal(got, in) {
			t.Fatalf("size %d: CORRUPTION — got %d bytes, want %d", n, len(got), n)
		}
	}
}

// TestFramedConnPadsSmallRecords proves the key capability that byte-preserving
// re-chunking lacks: a tiny application write is padded UP to at least
// MinRecordPayload on the wire (via a PAD frame the peer strips).
func TestFramedConnPadsSmallRecords(t *testing.T) {
	prof := testProfile()
	eng := NewCamouflageEngine(&CamouflageConfig{Profile: prof, Mode: ""})

	a, b := net.Pipe()
	cc := &countConn{Conn: a}
	client := NewFramedConn(cc, eng, C2S)
	server := NewFramedConn(b, eng, S2C)

	// Drain the server side so the synchronous pipe doesn't block the writer.
	drained := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				close(drained)
				return
			}
		}
	}()

	small := []byte("hi") // 2 bytes
	if _, err := client.Write(small); err != nil {
		t.Fatal(err)
	}
	a.Close()
	<-drained

	cc.mu.Lock()
	wrote := cc.written
	cc.mu.Unlock()

	if wrote < prof.MinRecordPayload {
		t.Fatalf("small write emitted %d wire bytes, expected padding up to >= MinRecordPayload %d",
			wrote, prof.MinRecordPayload)
	}
}

var _ = io.EOF
