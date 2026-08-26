// Package memtune sets a soft memory limit (GOMEMLIMIT) at startup so the Go GC
// runs harder as the process approaches the machine/container memory limit,
// instead of letting allocation churn balloon RSS into an OOM kill.
//
// This is the safe, in-process equivalent of a proxy backend's "large-TCP-
// connection memory optimization": on a busy multi-user node, mieru's per-
// segment buffers (writeOneSegment/writeChunk in enfein/mieru) and xray's
// per-connection buffers generate heavy short-lived allocations. Without a
// memory limit the Go runtime keeps RSS high (it only GCs on the GOGC growth
// ratio and is lazy about returning pages to the OS), which on a small VPS
// reads as "memory full" and eventually OOMs. Setting GOMEMLIMIT makes the GC
// ramp up automatically near the ceiling and hand memory back — it does not
// remove the churn (that CPU cost is addressed separately by requiring the
// mieru user hint), but it caps steady-state RSS.
//
// GOGC is deliberately left at its default: with GOMEMLIMIT set, the runtime
// already GCs more frequently only as it nears the limit, so there is no CPU
// penalty while memory use is low. An operator who sets GOMEMLIMIT (or
// V2NODE_MEM_LIMIT_RATIO) in the environment overrides everything here.
package memtune

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// cgroup v2 "max" and cgroup v1 "unlimited" sentinel are absurdly large; treat
// anything above this as "no cgroup limit set" and fall back to physical RAM.
const cgroupUnlimitedThreshold int64 = 1 << 60 // ~1.15 EiB

// Apply detects the effective memory limit for this process and sets
// GOMEMLIMIT to a fraction of it. It is a no-op when the operator already set
// GOMEMLIMIT, when detection fails (e.g. non-Linux dev machines with no
// /proc or /sys), or when the computed limit is not positive.
func Apply() {
	if v := strings.TrimSpace(os.Getenv("GOMEMLIMIT")); v != "" {
		// Operator override wins; the Go runtime already parsed it at startup.
		log.WithField("GOMEMLIMIT", v).Info("memtune: GOMEMLIMIT set by environment, leaving as-is")
		return
	}

	total := detectMemLimit()
	if total <= 0 {
		// Could not detect (non-Linux, or unreadable): leave the runtime default.
		return
	}

	ratio := ratioFromEnv()
	limit := int64(float64(total) * ratio)
	if limit <= 0 {
		return
	}

	setMemoryLimit(limit)
	log.WithFields(log.Fields{
		"detected_mib": total / (1 << 20),
		"limit_mib":    limit / (1 << 20),
		"ratio":        ratio,
	}).Info("memtune: auto GOMEMLIMIT applied")
}

// ratioFromEnv returns the fraction of detected memory to use as the soft
// limit. Default 0.8 leaves headroom for non-Go RSS (native buffers, THP,
// goroutine stacks) and the kernel. Override with V2NODE_MEM_LIMIT_RATIO in
// (0,1]; out-of-range or unparseable values fall back to the default.
func ratioFromEnv() float64 {
	const def = 0.8
	v := strings.TrimSpace(os.Getenv("V2NODE_MEM_LIMIT_RATIO"))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 || f > 1 {
		log.WithField("value", v).Warn("memtune: invalid V2NODE_MEM_LIMIT_RATIO, using default 0.8")
		return def
	}
	return f
}

// detectMemLimit returns the smaller of the cgroup memory limit (if any) and
// physical RAM, in bytes. Returns 0 if nothing could be read.
func detectMemLimit() int64 {
	machine := memTotalFromMeminfo()
	cg := cgroupMemLimit()
	if cg > 0 && cg < cgroupUnlimitedThreshold {
		if machine <= 0 || cg < machine {
			return cg
		}
	}
	return machine
}

// memTotalFromMeminfo reads MemTotal (kB) from /proc/meminfo and returns bytes.
func memTotalFromMeminfo() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// cgroupMemLimit reads the memory limit from cgroup v2 (memory.max) or v1
// (memory.limit_in_bytes). Returns 0 if unset/unreadable, or the raw value
// (which the caller filters against cgroupUnlimitedThreshold).
func cgroupMemLimit() int64 {
	// cgroup v2 unified hierarchy.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(b))
		if s == "max" {
			return 0
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
	}
	// cgroup v1.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			return n
		}
	}
	return 0
}
