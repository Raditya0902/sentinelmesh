package dashboard

import (
	"testing"
	"time"

	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

func makeEvent(reqID string, action policy.Action, blocked bool, ts time.Time) *DashboardEvent {
	return &DashboardEvent{
		ID: reqID,
		PipelineEvent: pipeline.PipelineEvent{
			Timestamp: ts,
			Direction: "ingress",
			RequestID: reqID,
			Action:    action,
			Blocked:   blocked,
		},
	}
}

// TestStats_UniqueRequestCount: ingress + egress for the same request_id counts as 1 request.
func TestStats_UniqueRequestCount(t *testing.T) {
	s := NewStats()
	now := time.Now().UTC()

	s.Record(makeEvent("req-1", policy.ActionAllow, false, now))
	s.Record(makeEvent("req-1", policy.ActionAllow, false, now.Add(500*time.Millisecond))) // egress

	snap := s.Snapshot()
	if snap.TotalRequests != 1 {
		t.Errorf("expected TotalRequests=1 for ingress+egress pair, got %d", snap.TotalRequests)
	}
	if snap.AllowedCount != 1 {
		t.Errorf("expected AllowedCount=1, got %d", snap.AllowedCount)
	}
	if snap.BlockedCount != 0 {
		t.Errorf("expected BlockedCount=0, got %d", snap.BlockedCount)
	}
}

// TestStats_AllowToBlockUpgrade: egress DENY after ingress ALLOW counts the request as blocked.
func TestStats_AllowToBlockUpgrade(t *testing.T) {
	s := NewStats()
	now := time.Now().UTC()

	s.Record(makeEvent("req-1", policy.ActionAllow, false, now))
	s.Record(makeEvent("req-1", policy.ActionDeny, true, now.Add(500*time.Millisecond)))

	snap := s.Snapshot()
	if snap.TotalRequests != 1 {
		t.Errorf("expected TotalRequests=1, got %d", snap.TotalRequests)
	}
	if snap.BlockedCount != 1 {
		t.Errorf("expected BlockedCount=1 after egress block, got %d", snap.BlockedCount)
	}
	if snap.AllowedCount != 0 {
		t.Errorf("expected AllowedCount=0 (upgraded to blocked), got %d", snap.AllowedCount)
	}
}

// TestStats_StreamingBlockUpgrade: ingress ALLOW + streaming_blocked DENY = 1 blocked request.
func TestStats_StreamingBlockUpgrade(t *testing.T) {
	s := NewStats()
	now := time.Now().UTC()

	ingressAllow := makeEvent("req-2", policy.ActionAllow, false, now)
	ingressDeny := makeEvent("req-2", policy.ActionDeny, true, now.Add(50*time.Millisecond))
	ingressDeny.RuleName = "streaming_blocked"

	s.Record(ingressAllow)
	s.Record(ingressDeny)

	snap := s.Snapshot()
	if snap.TotalRequests != 1 {
		t.Errorf("expected TotalRequests=1 for streaming block, got %d", snap.TotalRequests)
	}
	if snap.BlockedCount != 1 {
		t.Errorf("expected BlockedCount=1 for streaming block, got %d", snap.BlockedCount)
	}
}

// TestStats_TimeBucketBlockedCountUpgrade: the time-series blocked counter for the
// ingress minute is incremented retroactively when a later event upgrades ALLOW→DENY.
func TestStats_TimeBucketBlockedCountUpgrade(t *testing.T) {
	s := NewStats()
	now := time.Now().UTC()
	minute := now.Truncate(time.Minute)

	s.Record(makeEvent("req-1", policy.ActionAllow, false, now))

	snap1 := s.Snapshot()
	pt1 := findTimePoint(snap1.TimeSeries, minute)
	if pt1 == nil {
		t.Fatal("expected time-series point for current minute after ingress")
	}
	if pt1.Count != 1 {
		t.Errorf("expected count=1 in minute bucket, got %d", pt1.Count)
	}
	if pt1.Blocked != 0 {
		t.Errorf("expected blocked=0 in minute bucket before upgrade, got %d", pt1.Blocked)
	}

	// Egress block upgrades the same request to DENY.
	s.Record(makeEvent("req-1", policy.ActionDeny, true, now.Add(500*time.Millisecond)))

	snap2 := s.Snapshot()
	pt2 := findTimePoint(snap2.TimeSeries, minute)
	if pt2 == nil {
		t.Fatal("expected time-series point for current minute after upgrade")
	}
	if pt2.Count != 1 {
		t.Errorf("expected count=1 unchanged after upgrade, got %d", pt2.Count)
	}
	if pt2.Blocked != 1 {
		t.Errorf("expected blocked=1 after ALLOW→DENY upgrade in minute bucket, got %d", pt2.Blocked)
	}
}

// TestStats_TTLEvictionFinalizes: expired request_ids are removed from the active map
// and counted in the finalized lifetime counters so Snapshot totals remain correct.
func TestStats_TTLEvictionFinalizes(t *testing.T) {
	s := NewStats()
	now := time.Now().UTC()
	oldTS := now.Add(-(requestTTL + time.Second))

	// Record an old blocked request using a past timestamp.
	s.Record(makeEvent("req-old", policy.ActionDeny, true, oldTS))

	// The active map should have one entry before eviction.
	s.mu.RLock()
	activeBefore := len(s.requestRecords)
	s.mu.RUnlock()
	if activeBefore != 1 {
		t.Fatalf("expected 1 active record before eviction, got %d", activeBefore)
	}

	// A new event triggers eviction of entries older than requestTTL.
	s.Record(makeEvent("req-new", policy.ActionAllow, false, now))

	s.mu.RLock()
	activeAfter := len(s.requestRecords)
	s.mu.RUnlock()
	if activeAfter != 1 {
		t.Errorf("expected 1 active record after eviction (req-old evicted), got %d", activeAfter)
	}

	snap := s.Snapshot()
	if snap.TotalRequests != 2 {
		t.Errorf("expected TotalRequests=2 (1 finalized + 1 active), got %d", snap.TotalRequests)
	}
	if snap.BlockedCount != 1 {
		t.Errorf("expected BlockedCount=1 (finalized blocked req), got %d", snap.BlockedCount)
	}
	if snap.AllowedCount != 1 {
		t.Errorf("expected AllowedCount=1 (active allowed req), got %d", snap.AllowedCount)
	}
}

// TestStats_MultipleRequests: independent requests are counted separately.
func TestStats_MultipleRequests(t *testing.T) {
	s := NewStats()
	now := time.Now().UTC()

	s.Record(makeEvent("req-1", policy.ActionAllow, false, now))
	s.Record(makeEvent("req-2", policy.ActionDeny, true, now))
	s.Record(makeEvent("req-3", policy.ActionAllow, false, now))

	snap := s.Snapshot()
	if snap.TotalRequests != 3 {
		t.Errorf("expected TotalRequests=3, got %d", snap.TotalRequests)
	}
	if snap.BlockedCount != 1 {
		t.Errorf("expected BlockedCount=1, got %d", snap.BlockedCount)
	}
	if snap.AllowedCount != 2 {
		t.Errorf("expected AllowedCount=2, got %d", snap.AllowedCount)
	}
}

func findTimePoint(series []TimeSeriesPoint, minute time.Time) *TimeSeriesPoint {
	for i := range series {
		if series[i].Timestamp.Equal(minute) {
			return &series[i]
		}
	}
	return nil
}
