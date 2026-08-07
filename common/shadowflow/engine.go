package shadowflow

import (
	"sync"
	"sync/atomic"
)

// ====================================================================
// TLS Record Size Camouflage Engine
//
// Holds the per-node camouflage configuration (profile + mode). The actual
// reshaping — and, importantly, the per-connection profile selection and the
// per-connection initial-packet sequence — lives in ShapedBufWriter
// (writer.go). The engine itself is intentionally light: it carries config and
// a base profile, nothing more.
//
// Design note (why no shared dynamic switcher):
//   An earlier version ran one goroutine per node that periodically switched a
//   SHARED active profile. That was harmful for two reasons:
//     1. All of a node's connections switched size distribution in lockstep —
//        a cross-connection correlation signal no real browser produces.
//     2. The dispatcher caches engines per node tag and never Closes them, so
//        the goroutine leaked for the process lifetime.
//   Profile choice is now made per connection in NewShapedBufWriter, which
//   decorrelates connections and lets each replay the initial sequence.
// ====================================================================

// CamouflageConfig holds per-node camouflage settings.
type CamouflageConfig struct {
	// Profile for traffic shaping (base/default profile).
	Profile *TrafficProfile

	// Camouflage mode: "random", "dynamic", "web_browsing", "live_stream",
	// "file_download", "video_call", or "" (fixed to Profile).
	// "random"/"dynamic" make each connection pick its own random profile.
	Mode string

	// Retained for config compatibility; no longer drives a shared switcher.
	SwitchIntervalMin int
	SwitchIntervalMax int
}

// CamouflageEngine carries the camouflage config and base profile for a node.
type CamouflageEngine struct {
	config *CamouflageConfig

	// Base/active profile (used for fixed mode and as a fallback).
	activeProfile atomic.Value // *TrafficProfile

	stopCh  chan struct{}
	stopped atomic.Bool
	wg      sync.WaitGroup
}

// NewCamouflageEngine creates a new engine with the given config.
func NewCamouflageEngine(config *CamouflageConfig) *CamouflageEngine {
	e := &CamouflageEngine{
		config: config,
		stopCh: make(chan struct{}),
	}
	profile := config.Profile
	if profile == nil {
		profile = ChromeH2Profile
	}
	e.activeProfile.Store(profile)
	return e
}

// Close releases engine resources. Kept for API stability; currently the
// engine owns no goroutines.
func (e *CamouflageEngine) Close() {
	if e.stopped.CompareAndSwap(false, true) {
		close(e.stopCh)
		e.wg.Wait()
	}
}

// getProfile returns the base/active profile.
func (e *CamouflageEngine) getProfile() *TrafficProfile {
	return e.activeProfile.Load().(*TrafficProfile)
}

// Direction indicates traffic direction.
type Direction int

const (
	C2S Direction = iota
	S2C
)
