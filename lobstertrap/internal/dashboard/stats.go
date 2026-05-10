package dashboard

import (
	"sync"
	"time"
)

const (
	timeSeriesMinutes = 60
	// requestTTL is how long a request_id is kept in the active dedup window.
	// LLM calls finish in < 30 s; 2 minutes is a conservative upper bound.
	// Expired entries are finalized into lifetime counters and evicted.
	requestTTL = 2 * time.Minute
)

// requestRecord tracks the final outcome of a single proxied request.
type requestRecord struct {
	blocked     bool
	firstMinute time.Time // minute bucket of the first event, for time-series fixup
	lastSeen    time.Time // updated on every event; drives TTL eviction
}

// Stats accumulates real-time statistics from pipeline events.
//
// Each proxied request produces multiple pipeline events (ingress + egress,
// or ingress ALLOW + streaming_blocked DENY). Stats deduplicates by request_id
// so "Total Requests" counts unique calls, not audit rows.
//
// Memory: requestRecords holds only the active dedup window (entries within
// requestTTL of their last event). Finalized requests are counted in
// finalizedTotal / finalizedBlocked and then evicted from the map.
type Stats struct {
	mu sync.RWMutex

	// Active dedup window: recent request_ids with mutable block state.
	requestRecords map[string]*requestRecord

	// Lifetime counters for requests that have been evicted from requestRecords.
	finalizedTotal   uint64
	finalizedBlocked uint64

	// riskScoreSum / riskScoreN are sampled once per request (ingress only).
	riskScoreSum float64
	riskScoreN   uint64

	actionCounts map[string]uint64
	ruleCounts   map[string]uint64
	intentCounts map[string]uint64
	riskHist     [10]uint64 // buckets: [0.0-0.1), [0.1-0.2), ..., [0.9-1.0]

	timeBuckets [timeSeriesMinutes]timeBucket
}

type timeBucket struct {
	minute  time.Time
	count   uint64
	blocked uint64
}

// NewStats creates a new stats accumulator.
func NewStats() *Stats {
	return &Stats{
		requestRecords: make(map[string]*requestRecord),
		actionCounts:   make(map[string]uint64),
		ruleCounts:     make(map[string]uint64),
		intentCounts:   make(map[string]uint64),
	}
}

// Record ingests a single pipeline event.
func (s *Stats) Record(event *DashboardEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.evictExpired(event.Timestamp)

	rec, seen := s.requestRecords[event.RequestID]
	if !seen {
		// First event for this request_id (always an ingress event).
		rec = &requestRecord{
			blocked:     event.Blocked,
			firstMinute: event.Timestamp.Truncate(time.Minute),
			lastSeen:    event.Timestamp,
		}
		s.requestRecords[event.RequestID] = rec

		// Sample per-request metrics once (on the first/ingress event).
		if event.Metadata != nil {
			s.riskScoreSum += event.Metadata.RiskScore
			s.riskScoreN++

			bucket := min(int(event.Metadata.RiskScore*10), 9)
			s.riskHist[bucket]++

			if event.Metadata.IntentCategory != "" {
				s.intentCounts[event.Metadata.IntentCategory]++
			}
		}

		s.addTimeCount(rec.firstMinute, event.Blocked)
	} else {
		rec.lastSeen = event.Timestamp

		if event.Blocked && !rec.blocked {
			// Block state upgraded ALLOW→DENY (egress block or streaming_blocked).
			// Block state never reverses, so we only upgrade, never downgrade.
			rec.blocked = true
			s.upgradeTimeBlocked(rec.firstMinute)
		}
	}

	// Action and rule distributions track every event for audit granularity.
	s.actionCounts[string(event.Action)]++
	if event.RuleName != "" {
		s.ruleCounts[event.RuleName]++
	}
}

// evictExpired finalizes and removes requestRecords older than requestTTL.
// Must be called with s.mu held for writing.
func (s *Stats) evictExpired(now time.Time) {
	cutoff := now.Add(-requestTTL)
	for id, rec := range s.requestRecords {
		if rec.lastSeen.Before(cutoff) {
			s.finalizedTotal++
			if rec.blocked {
				s.finalizedBlocked++
			}
			delete(s.requestRecords, id)
		}
	}
}

// addTimeCount registers a new request in the appropriate minute bucket.
func (s *Stats) addTimeCount(minute time.Time, blocked bool) {
	idx := minute.Minute() % timeSeriesMinutes
	if !s.timeBuckets[idx].minute.Equal(minute) {
		s.timeBuckets[idx] = timeBucket{minute: minute}
	}
	s.timeBuckets[idx].count++
	if blocked {
		s.timeBuckets[idx].blocked++
	}
}

// upgradeTimeBlocked increments the blocked counter in the minute bucket where
// this request was first seen. Called when a later event upgrades ALLOW→DENY.
func (s *Stats) upgradeTimeBlocked(minute time.Time) {
	idx := minute.Minute() % timeSeriesMinutes
	if s.timeBuckets[idx].minute.Equal(minute) {
		s.timeBuckets[idx].blocked++
	}
}

// Snapshot returns a point-in-time copy of the stats.
func (s *Stats) Snapshot() *StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var activeBlocked uint64
	for _, rec := range s.requestRecords {
		if rec.blocked {
			activeBlocked++
		}
	}

	totalRequests := s.finalizedTotal + uint64(len(s.requestRecords))
	blockedCount := s.finalizedBlocked + activeBlocked

	snap := &StatsSnapshot{
		TotalRequests: totalRequests,
		BlockedCount:  blockedCount,
		AllowedCount:  totalRequests - blockedCount,
		ActionCounts:  copyMap(s.actionCounts),
		RuleCounts:    copyMap(s.ruleCounts),
		IntentCounts:  copyMap(s.intentCounts),
		RiskHistogram: s.riskHist,
	}

	if s.riskScoreN > 0 {
		snap.AvgRiskScore = s.riskScoreSum / float64(s.riskScoreN)
	}

	now := time.Now().UTC().Truncate(time.Minute)
	cutoff := now.Add(-timeSeriesMinutes * time.Minute)
	for i := range timeSeriesMinutes {
		t := cutoff.Add(time.Duration(i+1) * time.Minute)
		idx := t.Minute() % timeSeriesMinutes
		b := s.timeBuckets[idx]
		if b.minute.Equal(t) {
			snap.TimeSeries = append(snap.TimeSeries, TimeSeriesPoint{
				Timestamp: b.minute,
				Count:     b.count,
				Blocked:   b.blocked,
			})
		} else {
			snap.TimeSeries = append(snap.TimeSeries, TimeSeriesPoint{
				Timestamp: t,
			})
		}
	}

	return snap
}

func copyMap(m map[string]uint64) map[string]uint64 {
	c := make(map[string]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
