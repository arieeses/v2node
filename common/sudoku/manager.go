package sudoku

import (
	"fmt"
	"sync"

	"github.com/xtls/xray-core/features/routing"

	panel "github.com/wyx2685/v2node/api/v2board"
)

// Manager tracks one sudoku Runner per node tag. It is driven by V2Core's
// AddNode/DelNode/AddUsers/DelUsers for nodes whose protocol is "sudoku".
type Manager struct {
	mu      sync.Mutex
	runners map[string]*Runner
	disp    routing.Dispatcher
}

func NewManager() *Manager {
	return &Manager{runners: make(map[string]*Runner)}
}

// SetDispatcher wires Xray's dispatcher (available after the core starts).
func (m *Manager) SetDispatcher(d routing.Dispatcher) {
	m.mu.Lock()
	m.disp = d
	m.mu.Unlock()
}

// Add registers a sudoku runner for the node (idempotent per tag). The listener
// starts lazily on the first user (AddNode runs before AddUsers).
func (m *Manager) Add(tag string, info *panel.NodeInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.disp == nil {
		return fmt.Errorf("sudoku: dispatcher not set")
	}
	if _, ok := m.runners[tag]; ok {
		return nil
	}
	m.runners[tag] = NewRunner(tag, info, m.disp)
	return nil
}

func (m *Manager) Del(tag string) {
	m.mu.Lock()
	r, ok := m.runners[tag]
	if ok {
		delete(m.runners, tag)
	}
	m.mu.Unlock()
	if ok {
		_ = r.Close()
	}
}

func (m *Manager) Has(tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.runners[tag]
	return ok
}

// CloseAll stops every running sudoku server (used on full core shutdown/reload).
func (m *Manager) CloseAll() {
	m.mu.Lock()
	runners := m.runners
	m.runners = make(map[string]*Runner)
	m.mu.Unlock()
	for _, r := range runners {
		_ = r.Close()
	}
}

func (m *Manager) AddUsers(tag string, users []panel.UserInfo) error {
	m.mu.Lock()
	r := m.runners[tag]
	m.mu.Unlock()
	if r != nil {
		return r.AddUsers(users)
	}
	return nil
}

func (m *Manager) DelUsers(tag string, uuids []string) {
	m.mu.Lock()
	r := m.runners[tag]
	m.mu.Unlock()
	if r != nil {
		r.DelUsers(uuids)
	}
}
