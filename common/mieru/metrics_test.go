package mieru

import (
	"fmt"
	"testing"

	mmetrics "github.com/enfein/mieru/v3/pkg/metrics"
)

// Verify that pre-registering a user's counters as plain COUNTER makes mieru's
// later COUNTER_TIME_SERIES registration reuse them (LoadOrStore), so Add never
// builds the per-write protobuf history that caused the memory/GC blowup.
func TestPreRegisterKillsTimeSeries(t *testing.T) {
	uuid := "unit-test-uuid-abc"
	preRegisterUserMetrics(uuid)

	grp := fmt.Sprintf(mmetrics.UserMetricGroupFormat, uuid)
	// Simulate exactly what mieru's session code does.
	up := mmetrics.RegisterMetric(grp, mmetrics.UserMetricUploadBytes, mmetrics.COUNTER_TIME_SERIES)
	down := mmetrics.RegisterMetric(grp, mmetrics.UserMetricDownloadBytes, mmetrics.COUNTER_TIME_SERIES)

	if up.Type() != mmetrics.COUNTER {
		t.Fatalf("upload counter is time-series (%v) — fix ineffective", up.Type())
	}
	if down.Type() != mmetrics.COUNTER {
		t.Fatalf("download counter is time-series (%v) — fix ineffective", down.Type())
	}

	// Add a bunch; a plain counter must not grow history (value only).
	for i := 0; i < 5000; i++ {
		up.Add(1)
	}
	if up.Type() != mmetrics.COUNTER {
		t.Fatalf("type changed after Add")
	}
}
