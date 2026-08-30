package memtune

import (
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// heapProfilePath is where StartScavenger writes a fresh heap profile each
// cycle WHEN V2NODE_HEAP_DUMP=1, so a leak can be diagnosed without touching the
// pprof HTTP endpoint: just copy this file. Off by default.
const heapProfilePath = "/tmp/v2node-heap.prof"

// dumpHeapEnabled reports whether periodic heap-profile dumps are turned on.
var dumpHeapEnabled = func() bool {
	v := strings.TrimSpace(os.Getenv("V2NODE_HEAP_DUMP"))
	return v == "1" || strings.EqualFold(v, "true")
}()

// defaultScavengeInterval is how often to force freed heap memory back to the
// OS. The Go runtime's background scavenger returns memory only lazily (and,
// with a memory limit set, is content to keep pages up to that limit), so after
// a traffic peak recedes the freed heap stays resident and RSS sits at the
// high-water mark. A periodic debug.FreeOSMemory() makes RSS track the live
// working set instead — the same trick other proxy backends use to keep RSS
// low on small VPS. Each call triggers one GC, which is negligible next to the
// runtime's own GC rate on a busy node.
const defaultScavengeInterval = 120 * time.Second

// StartScavenger launches a background goroutine that periodically returns
// freed memory to the OS. The interval is set by V2NODE_MEM_SCAVENGE_SEC
// (seconds); unset uses the default, and 0 disables scavenging entirely (for
// operators who prefer the runtime's own pacing). It returns immediately.
func StartScavenger() {
	interval := scavengeIntervalFromEnv()
	if interval <= 0 {
		log.Info("memtune: periodic OS-memory scavenging disabled (V2NODE_MEM_SCAVENGE_SEC=0)")
		return
	}
	log.WithField("interval", interval.String()).Info("memtune: periodic OS-memory scavenging enabled")
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			// Force freed spans back to the OS so RSS falls after load peaks
			// instead of lingering at the high-water mark.
			debug.FreeOSMemory()

			// Log a memory snapshot every cycle so growth is visible in the
			// journal (heap climbing = a real leak; stable = working set), with
			// no need to run any pprof command.
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.WithFields(log.Fields{
				"heap_mb":    m.HeapAlloc / 1048576,
				"heapinuse":  m.HeapInuse / 1048576,
				"sys_mb":     m.Sys / 1048576,
				"goroutines": runtime.NumGoroutine(),
			}).Info("memtune: mem snapshot")

			// Optionally drop a fresh heap profile to disk so it can be analysed
			// offline (go tool pprof -inuse_space) without the HTTP endpoint.
			// Off by default — writing a profile every cycle is diagnostic
			// overhead; enable per-box with V2NODE_HEAP_DUMP=1 when investigating.
			if dumpHeapEnabled {
				if f, err := os.Create(heapProfilePath); err == nil {
					_ = pprof.WriteHeapProfile(f)
					_ = f.Close()
				}
			}
		}
	}()
}

// scavengeIntervalFromEnv parses V2NODE_MEM_SCAVENGE_SEC. Empty → default;
// "0" → disabled (returns 0); a positive integer → that many seconds; anything
// else → default (with a warning).
func scavengeIntervalFromEnv() time.Duration {
	v := strings.TrimSpace(os.Getenv("V2NODE_MEM_SCAVENGE_SEC"))
	if v == "" {
		return defaultScavengeInterval
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		log.WithField("value", v).Warn("memtune: invalid V2NODE_MEM_SCAVENGE_SEC, using default")
		return defaultScavengeInterval
	}
	return time.Duration(secs) * time.Second
}
