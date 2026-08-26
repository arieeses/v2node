package memtune

import (
	"os"
	"testing"
)

func TestRatioFromEnv(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0.8},
		{"0.5", 0.5},
		{"1", 1},
		{"0", 0.8},    // out of range -> default
		{"1.5", 0.8},  // out of range -> default
		{"-0.2", 0.8}, // out of range -> default
		{"abc", 0.8},  // unparseable -> default
	}
	for _, c := range cases {
		os.Setenv("V2NODE_MEM_LIMIT_RATIO", c.in)
		if got := ratioFromEnv(); got != c.want {
			t.Errorf("ratioFromEnv(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	os.Unsetenv("V2NODE_MEM_LIMIT_RATIO")
}

func TestDetectMemLimitNonNegative(t *testing.T) {
	// On Linux CI this reads real values; on dev machines it returns 0. Either
	// way it must never be negative, and cgroup "unlimited" must not leak
	// through as an absurd number.
	got := detectMemLimit()
	if got < 0 {
		t.Fatalf("detectMemLimit() = %d, want >= 0", got)
	}
	if got >= cgroupUnlimitedThreshold {
		t.Fatalf("detectMemLimit() = %d leaked an unlimited cgroup sentinel", got)
	}
}

func TestApplyNoPanic(t *testing.T) {
	// Smoke test: Apply must not panic regardless of platform. With GOMEMLIMIT
	// preset it should early-return without touching the runtime limit.
	os.Setenv("GOMEMLIMIT", "512MiB")
	Apply()
	os.Unsetenv("GOMEMLIMIT")
	Apply()
}
