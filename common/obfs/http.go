package obfs

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

const maxObfsHeader = 8 << 10 // cap the fake-HTTP request header we will read

// readHTTPRequest consumes the client's fake HTTP request headers up to and
// including the terminating blank line. The request body (the first chunk of
// the real Shadowsocks stream) is left unread in the buffered reader, so the
// raw read path serves it next. No payload is buffered here.
func (c *obfsConn) readHTTPRequest() error {
	read := 0
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return err
		}
		read += len(line)
		if read > maxObfsHeader {
			return fmt.Errorf("obfs-http: request header too large")
		}
		if line == "\r\n" || line == "\n" {
			return nil // end of headers; body follows in the stream
		}
	}
}

// buildHTTPResponse returns a fake "101 Switching Protocols" response followed
// by data. The reference client only scans for the "\r\n\r\n" header terminator
// and does not validate any field, so the exact headers are cosmetic.
func buildHTTPResponse(data []byte) []byte {
	accept := make([]byte, 20)
	_, _ = rand.Read(accept)
	head := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Server: nginx\r\n" +
		"Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(accept) + "\r\n" +
		"\r\n"
	out := make([]byte, 0, len(head)+len(data))
	out = append(out, head...)
	out = append(out, data...)
	return out
}
