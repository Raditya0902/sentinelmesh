package pipeline

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"os"
	"regexp"
	"sync"
	"time"
)

const (
	ruleHumanReviewApproved = "human_review_approved"
	reviewLedgerTTL         = 24 * time.Hour
	reviewLedgerMaxEntries  = 10_000
	maxDecisionLineBytes    = 1 << 20
	maxApprovalIDChars      = 64
)

var approvalIDPattern = regexp.MustCompile(`^req-[0-9a-f]+(-[0-9]+)?$`)

// validApprovalID rejects approval references that cannot be a proxy request ID.
func validApprovalID(id string) bool {
	return len(id) <= maxApprovalIDChars && approvalIDPattern.MatchString(id)
}

// ReviewApprovals answers whether a human approved a HUMAN_REVIEW request.
// since is when the review was raised: decisions older than that belong to an
// earlier request that reused the same (per-process, sequential) request ID.
type ReviewApprovals interface {
	IsApproved(requestID string, since time.Time) bool
}

// FileReviewApprovals reads the review decisions JSONL written by the SentinelMesh
// API (POST /review/{id}/decide). Decisions are write-once: the FIRST decision for a
// request ID wins, so a later line can never flip a reject into an approve.
type FileReviewApprovals struct {
	Path string
	// MaxAge bounds how long after a decision the approval may be used (0 = no limit).
	MaxAge time.Duration
	// Now is the clock (defaults to time.Now).
	Now func() time.Time
}

type reviewDecision struct {
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
	DecidedAt string `json:"decided_at"`
}

// IsApproved implements ReviewApprovals. A missing or unreadable file approves nothing.
func (f FileReviewApprovals) IsApproved(requestID string, since time.Time) bool {
	fh, err := os.Open(f.Path)
	if err != nil {
		return false
	}
	defer fh.Close()

	first, ok := firstDecision(fh, requestID)
	if !ok || first.Decision != "approve" {
		return false
	}
	decidedAt, err := time.Parse(time.RFC3339Nano, first.DecidedAt)
	if err != nil || decidedAt.Before(since) {
		return false
	}
	return f.MaxAge == 0 || f.now().Sub(decidedAt) <= f.MaxAge
}

func (f FileReviewApprovals) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// firstDecision returns the first decision for requestID. Any read error (e.g. an
// over-long line) fails closed, since the unread part could hold the real decision.
func firstDecision(fh *os.File, requestID string) (reviewDecision, bool) {
	scanner := bufio.NewScanner(fh)
	scanner.Buffer(make([]byte, 0, 64*1024), maxDecisionLineBytes)
	var found *reviewDecision
	for scanner.Scan() {
		var d reviewDecision
		if json.Unmarshal(scanner.Bytes(), &d) != nil || d.RequestID != requestID {
			continue
		}
		if found == nil {
			found = &d
		}
	}
	if scanner.Err() != nil || found == nil {
		return reviewDecision{}, false
	}
	return *found, true
}

type pendingReview struct {
	promptHash [32]byte
	agentID    string
	createdAt  time.Time
}

// reviewLedger remembers which prompt (and agent) each HUMAN_REVIEW request ID was
// raised for, so an approval can only release that exact prompt, once.
type reviewLedger struct {
	mu      sync.Mutex
	entries map[string]pendingReview
	now     func() time.Time
}

func newReviewLedger() *reviewLedger {
	return &reviewLedger{entries: make(map[string]pendingReview), now: time.Now}
}

// requestFingerprint binds an approval to the agent, its declared intent, the
// inspected prompt text, and the full forwarded body (model, tools, params...).
func requestFingerprint(req IngressRequest) [32]byte {
	agentID, intent := "", ""
	if req.Declared != nil {
		agentID, intent = req.Declared.AgentID, req.Declared.DeclaredIntent
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(agentID), []byte(intent), []byte(req.Prompt), req.Body} {
		h.Write(part)
		h.Write([]byte{0})
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func (l *reviewLedger) record(requestID, agentID string, fingerprint [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictLocked()
	l.entries[requestID] = pendingReview{
		promptHash: fingerprint,
		agentID:    agentID,
		createdAt:  l.now(),
	}
}

// consume returns true and forgets the entry when requestID is pending for exactly
// this agent+request and approvals confirms a human approved it after it was raised.
// The decisions file is read outside the ledger lock so slow I/O never blocks record().
func (l *reviewLedger) consume(requestID, agentID string, fingerprint [32]byte, approvals ReviewApprovals) bool {
	l.mu.Lock()
	entry, ok := l.entries[requestID]
	l.mu.Unlock()
	if !ok || entry.agentID != agentID || entry.promptHash != fingerprint {
		return false
	}
	if !approvals.IsApproved(requestID, entry.createdAt) {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, still := l.entries[requestID]; !still {
		return false // a concurrent replay already used this approval
	}
	delete(l.entries, requestID)
	return true
}

func (l *reviewLedger) evictLocked() {
	cutoff := l.now().Add(-reviewLedgerTTL)
	for id, e := range l.entries {
		if e.createdAt.Before(cutoff) {
			delete(l.entries, id)
		}
	}
	for len(l.entries) >= reviewLedgerMaxEntries {
		var oldestID string
		var oldest time.Time
		for id, e := range l.entries {
			if oldestID == "" || e.createdAt.Before(oldest) {
				oldestID, oldest = id, e.createdAt
			}
		}
		delete(l.entries, oldestID)
	}
}
