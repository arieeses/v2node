package memtune

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// memStatsPath holds the latest memory breakdown, rewritten every scavenge
// cycle so `cat /tmp/v2node-mem.txt` shows the current numbers regardless of
// the configured log level.
const memStatsPath = "/tmp/v2node-mem.txt"

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
			// Full breakdown so the cause is unambiguous from ONE line:
			//  - heapinuse high & growing        -> live heap leak (a real leak)
			//  - stack_mb high & growing          -> goroutine leak (leak in stacks)
			//  - heapsys>>heapinuse, released low -> Go holding freed heap (GOMEMLIMIT)
			const mb = 1048576
			log.WithFields(log.Fields{
				"heapinuse":  m.HeapInuse / mb,  // live+recently-freed heap in use
				"heapsys":    m.HeapSys / mb,    // heap reserved from OS
				"released":   m.HeapReleased / mb, // heap already returned to OS
				"stack_mb":   m.StackInuse / mb, // goroutine stacks (NOT in heap profile)
				"sys_mb":     m.Sys / mb,        // total from OS (~RSS)
				"goroutines": runtime.NumGoroutine(),
			}).Info("memtune: mem snapshot")

			// Also write the breakdown to a file so it is readable regardless of
			// log level — `cat /tmp/v2node-mem.txt` shows the current numbers, no
			// journal, no pprof, no restart-to-capture needed.
			line := fmt.Sprintf("heapinuse=%dMB heapsys=%dMB released=%dMB stack=%dMB sys=%dMB goroutines=%d\n",
				m.HeapInuse/mb, m.HeapSys/mb, m.HeapReleased/mb, m.StackInuse/mb, m.Sys/mb, runtime.NumGoroutine())
			_ = os.WriteFile(memStatsPath, []byte(line), 0644)

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
