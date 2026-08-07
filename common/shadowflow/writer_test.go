package shadowflow

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// bytesToMB builds a buf.MultiBuffer from a byte slice (split into buffers).
func bytesToMB(b []byte) buf.MultiBuffer {
	var mb buf.MultiBuffer
	for len(b) > 0 {
		buffer := buf.New()
		n, _ := buffer.Write(b)
		mb = append(mb, buffer)
		b = b[n:]
	}
	return mb
}

// collectWriter concatenates every buffer it receives.
type collectWriter struct{ data []byte }

func (c *collectWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		c.data = append(c.data, b.Bytes()...)
	}
	buf.ReleaseMulti(mb)
	return nil
}

func testProfile() *TrafficProfile {
	return &TrafficProfile{
		Name:             "test",
		C2SSizes:         []SizeRange{{Min: 40, Max: 300, Weight: 1}},
		S2CSizes:         []SizeRange{{Min: 40, Max: 300, Weight: 1}},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
		// InterPacketDelay* left 0 → no sleeps in tests
	}
}

// TestShapedBufWriterByteExact is the critical guarantee: shaping must never
// add or drop a single byte, across sizes that exercise the old truncation
// (>8192) and old padding-corruption (<MinRecordPayload) bugs.
func TestShapedBufWriterByteExact(t *testing.T) {
	eng := NewCamouflageEngine(&CamouflageConfig{Profile: testProfile(), Mode: ""})

	for _, n := range []int{0, 1, 5, 25, 26, 27, 51, 52, 100, 8191, 8192, 8193, 16384, 16385, 40000, 123457} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i*31 + 7)
		}
		cw := &collectWriter{}
		w := NewShapedBufWriter(cw, eng, S2C)
		if err := w.WriteMultiBuffer(bytesToMB(in)); err != nil {
			t.Fatalf("size %d: write error %v", n, err)
		}
		if !bytes.Equal(cw.data, in) {
			t.Fatalf("size %d: CORRUPTION — output %d bytes != input %d bytes", n, len(cw.data), n)
		}
	}
}

// sizeRecW records the size of every emitted record.
type sizeRecW struct{ sizes []int }

func (c *sizeRecW) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		c.sizes = append(c.sizes, int(b.Len()))
	}
	buf.ReleaseMulti(mb)
	return nil
}

// TestShapedBufWriterRecordBounds verifies records never exceed MaxRecordPayload
// (fits a TLS record) and no non-final record falls below MinRecordPayload.
func TestShapedBufWriterRecordBounds(t *testing.T) {
	prof := testProfile()
	eng := NewCamouflageEngine(&CamouflageConfig{Profile: prof, Mode: ""})

	in := make([]byte, 200000)
	cw := &sizeRecW{}
	w := NewShapedBufWriter(cw, eng, S2C)
	if err := w.WriteMultiBuffer(bytesToMB(in)); err != nil {
		t.Fatal(err)
	}
	total := 0
	for i, s := range cw.sizes {
		total += s
		if s > prof.MaxRecordPayload {
			t.Fatalf("record %d exceeds MaxRecordPayload %d", s, prof.MaxRecordPayload)
		}
		if i < len(cw.sizes)-1 && s < prof.MinRecordPayload {
			t.Fatalf("non-final record %d below MinRecordPayload %d", s, prof.MinRecordPayload)
		}
	}
	if total != len(in) {
		t.Fatalf("record sizes sum %d != input %d", total, len(in))
	}
}
