package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// makeClientHelloMsg mirrors mihomo/clash simple-obfs (transport/simple-obfs/
// tls.go) exactly, so the test drives the real client wire format against our
// server-side de-obfuscator.
func makeClientHelloMsg(data []byte, server string) []byte {
	random := make([]byte, 28)
	sessionID := make([]byte, 32)
	rand.Read(random)
	rand.Read(sessionID)

	buf := &bytes.Buffer{}
	buf.WriteByte(22)
	buf.Write([]byte{0x03, 0x01})
	length := uint16(212 + len(data) + len(server))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length & 0xff))

	buf.WriteByte(1)
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, uint16(208+len(data)+len(server)))
	buf.Write([]byte{0x03, 0x03})

	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	buf.Write(random)
	buf.WriteByte(32)
	buf.Write(sessionID)

	buf.Write([]byte{0x00, 0x38})
	buf.Write([]byte{
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
		0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
		0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
	})
	buf.Write([]byte{0x01, 0x00})
	binary.Write(buf, binary.BigEndian, uint16(79+len(data)+len(server)))

	buf.Write([]byte{0x00, 0x23})
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)

	buf.Write([]byte{0x00, 0x00})
	binary.Write(buf, binary.BigEndian, uint16(len(server)+5))
	binary.Write(buf, binary.BigEndian, uint16(len(server)+3))
	buf.WriteByte(0)
	binary.Write(buf, binary.BigEndian, uint16(len(server)))
	buf.Write([]byte(server))

	buf.Write([]byte{0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02})
	buf.Write([]byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18})
	buf.Write([]byte{
		0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
		0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
		0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	})
	buf.Write([]byte{0x00, 0x16, 0x00, 0x00})
	buf.Write([]byte{0x00, 0x17, 0x00, 0x00})
	return buf.Bytes()
}

// clientReadResponse mirrors mihomo TLSObfs.Read: strip 105 bytes on the first
// server record (ServerHello 96 + CCS 6 + record header 3), then 3 bytes on
// each following record, reading the 2-byte length and payload each time.
func clientReadResponse(t *testing.T, r io.Reader, first bool) []byte {
	t.Helper()
	discard := 3
	if first {
		discard = 105
	}
	if _, err := io.ReadFull(r, make([]byte, discard)); err != nil {
		t.Fatalf("discard header: %v", err)
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		t.Fatalf("read len: %v", err)
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return out
}

func TestObfsHTTPRoundTrip(t *testing.T) {
	cliRaw, srvRaw := net.Pipe()
	defer cliRaw.Close()
	defer srvRaw.Close()

	first := []byte("ss2022-first-chunk-in-http-body")
	second := bytes.Repeat([]byte("C"), 5000)
	resp1 := []byte("first-server-response")
	resp2 := bytes.Repeat([]byte("D"), 5000)

	sc := newObfsConn(srvRaw, modeHTTP)

	// Client: fake HTTP GET with first payload as body, then raw writes.
	go func() {
		req := "GET / HTTP/1.1\r\n" +
			"Host: www.bing.com:41228\r\n" +
			"User-Agent: curl/7.28.1\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Key: EfDKS-sTzw06jWkcXDIztw==\r\n" +
			"Content-Length: " + itoa(len(first)) + "\r\n\r\n"
		_, _ = cliRaw.Write(append([]byte(req), first...))
		_, _ = cliRaw.Write(second) // raw, unframed
	}()

	want := append(append([]byte{}, first...), second...)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 4096)
	for len(got) < len(want) {
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("http de-obfs mismatch: got %d want %d", len(got), len(want))
	}

	// Server writes; client strips the response headers, rest is raw.
	go func() {
		_, _ = sc.Write(resp1)
		_, _ = sc.Write(resp2)
	}()

	// Client-side: read until \r\n\r\n, everything after is raw payload.
	br := make([]byte, 65536)
	n, err := cliRaw.Read(br)
	if err != nil {
		t.Fatalf("client read resp: %v", err)
	}
	idx := bytes.Index(br[:n], []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatalf("no header terminator in response")
	}
	body := append([]byte{}, br[idx+4:n]...)
	wantResp := append(append([]byte{}, resp1...), resp2...)
	for len(body) < len(wantResp) {
		n, err = cliRaw.Read(br)
		if err != nil {
			t.Fatalf("client read raw: %v", err)
		}
		body = append(body, br[:n]...)
	}
	if !bytes.Equal(body, wantResp) {
		t.Fatalf("http response mismatch: got %d want %d", len(body), len(wantResp))
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func TestObfsTLSRoundTrip(t *testing.T) {
	cliRaw, srvRaw := net.Pipe()
	defer cliRaw.Close()
	defer srvRaw.Close()

	server := "www.bing.com"
	first := []byte("hello-shadowsocks-2022-initial-packet")
	second := bytes.Repeat([]byte("A"), 20000) // spans multiple app-data records
	resp1 := []byte("server-response-one")
	resp2 := bytes.Repeat([]byte("B"), 40000)

	sc := newObfsConn(srvRaw, modeTLS)

	// Client goroutine: send ClientHello(first) then app-data(second).
	go func() {
		_, _ = cliRaw.Write(makeClientHelloMsg(first, server))
		// second, chunked at 16384 like the client Write loop.
		for i := 0; i < len(second); i += maxRecord {
			end := i + maxRecord
			if end > len(second) {
				end = len(second)
			}
			_, _ = cliRaw.Write(wrapAppData(second[i:end]))
		}
	}()

	// Server reads the de-obfuscated plaintext and checks it equals first+second.
	want := append(append([]byte{}, first...), second...)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 4096)
	for len(got) < len(want) {
		n, err := sc.Read(buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("de-obfuscated mismatch: got %d bytes, want %d", len(got), len(want))
	}

	// Server writes responses; client decodes them with the mihomo framing.
	go func() {
		_, _ = sc.Write(resp1)
		_, _ = sc.Write(resp2)
	}()

	r1 := clientReadResponse(t, cliRaw, true)
	if !bytes.Equal(r1, resp1) {
		t.Fatalf("resp1 mismatch: got %q", r1)
	}
	// resp2 is chunked into 16384-byte records by Write; reassemble.
	got2 := make([]byte, 0, len(resp2))
	for len(got2) < len(resp2) {
		got2 = append(got2, clientReadResponse(t, cliRaw, false)...)
	}
	if !bytes.Equal(got2, resp2) {
		t.Fatalf("resp2 mismatch: got %d bytes, want %d", len(got2), len(resp2))
	}
}
