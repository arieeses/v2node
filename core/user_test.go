package core

import (
	"testing"

	"github.com/wyx2685/v2node/common/counter"
	"github.com/wyx2685/v2node/core/app/dispatcher"
)

// TestGetUserTrafficSlicePrunesOrphan verifies orphan counters (email no longer
// in uidMap) are pruned even when their traffic is below the mintraffic
// threshold, while a valid sub-threshold user is left intact.
func TestGetUserTrafficSlicePrunesOrphan(t *testing.T) {
	vc := &V2Core{
		users:      &UserMap{},
		dispatcher: &dispatcher.DefaultDispatcher{},
	}
	const tag = "tg"
	tc := counter.NewTrafficCounter()

	// valid user: present in uidMap, sub-threshold traffic
	const validEmail = "valid@x"
	vc.users.uidMap.Store(validEmail, 1)
	tc.GetCounter(validEmail).UpCounter.Store(10)

	// orphan user: NOT in uidMap, sub-threshold traffic
	const orphanEmail = "orphan@x"
	tc.GetCounter(orphanEmail).UpCounter.Store(5)

	vc.dispatcher.Counter.Store(tag, tc)

	// high mintraffic so both are below the report threshold
	if _, err := vc.GetUserTrafficSlice(tag, 1_000_000); err != nil {
		t.Fatalf("GetUserTrafficSlice: %v", err)
	}

	if _, ok := tc.Counters.Load(orphanEmail); ok {
		t.Fatal("orphan counter must be pruned regardless of traffic threshold")
	}
	if _, ok := tc.Counters.Load(validEmail); !ok {
		t.Fatal("valid user's counter must be retained")
	}
}
