package limiter

import (
	"fmt"
	"sync"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

// TestCheckLimitConcurrent hammers CheckLimit from many goroutines making their
// first connection for the same user simultaneously, stressing the LoadOrStore
// race branch of the refactor. Run under -race. DeviceLimit=0 so no rejects —
// the goal is to catch data races / panics in the shared-map handling.
func TestCheckLimitConcurrent(t *testing.T) {
	Init()
	const tag, uuid, uid = "tc", "uc", 400
	l := AddLimiter("v2ray", tag, []panel.UserInfo{{Id: uid, Uuid: uuid, DeviceLimit: 0}}, map[int]int{uid: 0})
	tu := format.UserTag(tag, uuid)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.%d.%d", n/256, n%256)
			for j := 0; j < 200; j++ {
				if _, rej := l.CheckLimit(tu, ip, true); rej {
					t.Errorf("unlimited user must never be rejected")
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestCheckLimitDevice exercises the refactored (allocation-free) device-limit
// path in CheckLimit: first device, returning ip, new ip under/over the limit.
func TestCheckLimitDevice(t *testing.T) {
	Init()
	const tag, uuid, uid = "t", "u1", 100
	l := AddLimiter("v2ray", tag, []panel.UserInfo{{Id: uid, Uuid: uuid, DeviceLimit: 2}}, map[int]int{uid: 1})
	tu := format.UserTag(tag, uuid)

	if _, rej := l.CheckLimit(tu, "1.1.1.1", true); rej {
		t.Fatal("case1: first device under limit must be accepted")
	}
	if _, rej := l.CheckLimit(tu, "1.1.1.1", true); rej {
		t.Fatal("case2: returning same ip must be accepted (no double count)")
	}
	if _, rej := l.CheckLimit(tu, "2.2.2.2", true); rej {
		t.Fatal("case3: new ip while under limit must be accepted")
	}

	l.UpdateAliveList(map[int]int{uid: 2}) // panel now reports user at the limit
	if _, rej := l.CheckLimit(tu, "3.3.3.3", true); !rej {
		t.Fatal("case4: new ip at device limit must be rejected")
	}
	if _, rej := l.CheckLimit(tu, "1.1.1.1", true); rej {
		t.Fatal("case5: already-tracked ip must be accepted even at limit")
	}
}

// TestCheckLimitReturningDevice verifies that after a report cycle
// (GetOnlineDevice moves ips into OldUserOnline and clears UserOnlineIP), a
// returning device is still accepted at the limit, while a brand-new device is
// rejected. This is the first-device branch of the refactor.
func TestCheckLimitReturningDevice(t *testing.T) {
	Init()
	const tag, uuid, uid = "t2", "u2", 200
	l := AddLimiter("v2ray", tag, []panel.UserInfo{{Id: uid, Uuid: uuid, DeviceLimit: 1}}, map[int]int{uid: 0})
	tu := format.UserTag(tag, uuid)

	if _, rej := l.CheckLimit(tu, "1.1.1.1", true); rej {
		t.Fatal("setup: first device must be accepted")
	}
	l.GetOnlineDevice()                    // -> OldUserOnline{1.1.1.1}, UserOnlineIP cleared
	l.UpdateAliveList(map[int]int{uid: 1}) // panel now at the limit

	if _, rej := l.CheckLimit(tu, "1.1.1.1", true); rej {
		t.Fatal("returning device must be accepted even at limit")
	}
	if _, rej := l.CheckLimit(tu, "9.9.9.9", true); !rej {
		t.Fatal("new device at limit must be rejected")
	}
}

// TestCheckLimitUnlimited verifies DeviceLimit=0 never rejects, regardless of
// the panel's alive count.
func TestCheckLimitUnlimited(t *testing.T) {
	Init()
	const tag, uuid, uid = "t3", "u3", 300
	l := AddLimiter("v2ray", tag, []panel.UserInfo{{Id: uid, Uuid: uuid, DeviceLimit: 0}}, map[int]int{uid: 999})
	tu := format.UserTag(tag, uuid)
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if _, rej := l.CheckLimit(tu, ip, true); rej {
			t.Fatalf("unlimited: ip %s must be accepted", ip)
		}
	}
}

// TestCheckLimitUnknownUser verifies an unknown user (not in UserLimitInfo) is
// rejected.
func TestCheckLimitUnknownUser(t *testing.T) {
	Init()
	l := AddLimiter("v2ray", "t4", nil, nil)
	if _, rej := l.CheckLimit(format.UserTag("t4", "ghost"), "1.1.1.1", true); !rej {
		t.Fatal("unknown user must be rejected")
	}
}
