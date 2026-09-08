// Package compat backports three network interfaces that sing added in v0.8.12
// (VectorisedWriteCreator, PacketBatchWriter, PacketBatchWriteCreator) so this
// vendored copy of sing-snell compiles against the sing v0.8.9 that the rest of
// v2node (and its vendored xray-core) pins. The definitions are byte-identical
// to upstream v0.8.12. sing v0.8.9's bufio/copy paths never look for these
// interfaces, so the vectorised / packet-batch fast paths simply fall back to
// the regular per-buffer writes — correct, only marginally less optimal. When
// v2node eventually moves to sing v0.8.12 everywhere, delete this package and
// change the `compat.` references back to `N.`.
package compat

import (
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type VectorisedWriteCreator interface {
	CreateVectorisedWriter() (N.VectorisedWriter, bool)
}

type PacketBatchWriter interface {
	WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error
}

type PacketBatchWriteCreator interface {
	CreatePacketBatchWriter() (PacketBatchWriter, bool)
}

// NewBufferSize backports ReadWaitOptions.NewBufferSize (added in sing v0.8.12):
// allocate a buffer sized for bufferSize plus the option's head/rear headroom.
// Identical to upstream. Call as compat.NewBufferSize(o, size) in place of
// o.NewBufferSize(size).
func NewBufferSize(o N.ReadWaitOptions, bufferSize int) *buf.Buffer {
	bufferSize += o.FrontHeadroom + o.RearHeadroom
	buffer := buf.NewSize(bufferSize)
	if o.FrontHeadroom > 0 {
		buffer.Resize(o.FrontHeadroom, 0)
	}
	if o.RearHeadroom > 0 {
		buffer.Reserve(o.RearHeadroom)
	}
	return buffer
}
