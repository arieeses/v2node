package memtune

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

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
