package memtune

import "runtime/debug"

// setMemoryLimit applies the computed soft limit to the Go runtime. Isolated so
// the detection logic in memtune.go stays free of the runtime/debug import and
// is unit-testable without mutating the process-wide GC limit.
func setMemoryLimit(limit int64) {
	debug.SetMemoryLimit(limit)
}
