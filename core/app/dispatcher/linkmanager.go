package dispatcher

import (
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

type LinkManager struct {
	links  map[*ManagedWriter]buf.Reader
	mu     sync.RWMutex
	closed bool
}

func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.links[writer] = reader
	}
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		delete(m.links, writer)
	}
}

// CloseAll force-closes every live connection of a removed user.
//
// It must NOT hold m.mu while closing, and must close the inner w.writer
// rather than the *ManagedWriter: ManagedWriter.Close() calls back into
// RemoveWriter -> m.mu.Lock(), so closing w (or iterating under the lock)
// self-deadlocks on this non-reentrant mutex — hanging the DelUsers goroutine
// and leaking the whole LinkManager (links, ManagedWriters, readers, pipe
// buffers, connection goroutines). Snapshot the map, release the lock, then
// close. The `closed` flag turns concurrent in-flight RemoveWriter/AddLink
// calls into safe no-ops.
func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	links := m.links
	m.links = make(map[*ManagedWriter]buf.Reader)
	m.mu.Unlock()

	for w, r := range links {
		common.Close(w.writer)
		common.Interrupt(r)
	}
}
