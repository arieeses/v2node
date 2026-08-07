package shadowflow

import (
	mathrand "math/rand"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// ====================================================================
// Xray buf.Writer Adapter
//
// Integrates the TLS Record Size camouflage engine into Xray's
// buf.Writer pipeline. This is injected into the dispatcher's
// link chain, sitting between the inbound handler and outbound handler.
//
// Data flow:
//   Client → TLS(Reality) → Xray Inbound → [ShapedBufWriter] → Outbound
//   Outbound → [ShapedBufWriter] → Xray Inbound → TLS(Reality) → Client
//
// IMPORTANT — byte-preserving shaping:
//   This writer only RE-CHUNKS the stream (changing TLS record boundaries)
//   to match a browser traffic profile. It NEVER adds or drops bytes.
//   ShadowFlow rides raw VLESS passthrough, which has no inner framing to
//   strip padding on the peer side, so any added byte would corrupt the
//   proxied stream. Small records that fall below MinRecordPayload are
//   avoided by *merging* them into the neighbouring record, not by padding.
// ====================================================================

// ShapedBufWriter wraps an Xray buf.Writer with camouflage shaping.
type ShapedBufWriter struct {
	writer  buf.Writer
	engine  *CamouflageEngine
	dir     Direction
	profile *TrafficProfile // per-connection profile (decorrelated across connections)
	initIdx int             // per-connection initial-sequence position
	mu      sync.Mutex
}

// NewShapedBufWriter creates a buf.Writer adapter with traffic shaping.
//
// The profile and the initial-sequence counter are held PER CONNECTION (not
// shared per node). This fixes two detection weaknesses of a shared engine:
//   - every connection replays the initial-packet sequence independently
//     (a shared counter would only shape the very first connection);
//   - connections do not switch profiles in lockstep (synchronized switches
//     across many connections are themselves a correlation fingerprint).
func NewShapedBufWriter(writer buf.Writer, engine *CamouflageEngine, dir Direction) buf.Writer {
	prof := engine.getProfile()
	if engine.config != nil && (engine.config.Mode == "dynamic" || engine.config.Mode == "random") {
		if p := GetRandomProfile(); p != nil {
			prof = p
		}
	}
	return &ShapedBufWriter{
		writer:  writer,
		engine:  engine,
		dir:     dir,
		profile: prof,
	}
}

// WriteMultiBuffer reshapes record sizes to match the profile WITHOUT changing
// the byte stream — it only re-chunks (splits/merges) into profile-conforming
// record sizes.
func (w *ShapedBufWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	totalLen := mb.Len()
	if totalLen == 0 {
		return w.writer.WriteMultiBuffer(mb)
	}

	// Flatten the incoming buffers into one contiguous slice for reshaping.
	data := make([]byte, 0, totalLen)
	for _, b := range mb {
		data = append(data, b.Bytes()...)
	}
	buf.ReleaseMulti(mb)

	// Plan record sizes under the lock (mutates the per-connection initIdx).
	w.mu.Lock()
	prof := w.profile
	sizes := w.planChunks(prof, len(data))
	w.mu.Unlock()

	shaped := make(buf.MultiBuffer, 0, len(sizes))
	offset := 0
	for i, sz := range sizes {
		// Inter-packet timing jitter between chunks (not before the first).
		if i > 0 && prof.InterPacketDelayMax > 0 {
			delay := prof.InterPacketDelayMin
			if prof.InterPacketDelayMax > prof.InterPacketDelayMin {
				delay += mathrand.Intn(prof.InterPacketDelayMax - prof.InterPacketDelayMin)
			}
			if delay > 0 {
				time.Sleep(time.Duration(delay) * time.Microsecond)
			}
		}

		// buf.NewWithSize guarantees capacity >= sz, so no truncation even for
		// records up to MaxRecordPayload (16384) — larger than the default 8192.
		b := buf.NewWithSize(int32(sz))
		if _, err := b.Write(data[offset : offset+sz]); err != nil {
			b.Release()
			buf.ReleaseMulti(shaped)
			return err
		}
		shaped = append(shaped, b)
		offset += sz
	}

	return w.writer.WriteMultiBuffer(shaped)
}

// planChunks returns record sizes that sum EXACTLY to dataLen (no bytes added
// or dropped). Each size is sampled from the profile, bounded to
// [MinRecordPayload, MaxRecordPayload]. A would-be sub-minimum trailing record
// is avoided by pulling bytes back into it (or, for a whole write smaller than
// two minimum records, emitted as a single small record — unavoidable and
// still byte-correct). Caller holds w.mu.
func (w *ShapedBufWriter) planChunks(prof *TrafficProfile, dataLen int) []int {
	min := prof.MinRecordPayload
	if min < 1 {
		min = 1
	}
	var sizes []int
	remaining := dataLen
	for remaining > 0 {
		t := w.nextTargetSize(prof)
		if t >= remaining {
			sizes = append(sizes, remaining)
			break
		}
		// Don't leave a sub-minimum tail: keep the tail >= min by taking less now.
		if remaining-t < min {
			t = remaining - min
			if t < min {
				// Whole remainder is small enough to be one record.
				sizes = append(sizes, remaining)
				break
			}
		}
		sizes = append(sizes, t)
		remaining -= t
	}
	return sizes
}

// nextTargetSize samples the next record size, advancing this connection's own
// initial-sequence index (per-connection, not shared across the node).
func (w *ShapedBufWriter) nextTargetSize(prof *TrafficProfile) int {
	var size int
	switch w.dir {
	case C2S:
		size = SampleInitialSize(prof.C2SInitial, w.initIdx)
		if size > 0 {
			w.initIdx++
		} else {
			size = SampleSize(prof.C2SSizes)
		}
	case S2C:
		size = SampleInitialSize(prof.S2CInitial, w.initIdx)
		if size > 0 {
			w.initIdx++
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
	return size
}

// Close implements common.Closable.
func (w *ShapedBufWriter) Close() error {
	if closer, ok := w.writer.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
