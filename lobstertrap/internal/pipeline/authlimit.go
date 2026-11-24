package pipeline

import (
	"sync"
	"time"

	"github.com/coal/lobstertrap/internal/policy"
)

const (
	// DefaultAuthFailuresPerWindow failed agent authentications from one IP lock it
	// out for the rest of DefaultAuthFailureWindow.
	DefaultAuthFailuresPerWindow = 10
	DefaultAuthFailureWindow     = time.Minute
	// maxTrackedAuthIPs caps the limiter's memory under a spray from many addresses.
	maxTrackedAuthIPs = 10_000

	ruleAgentAuthRateLimited = "agent_auth_rate_limited"
	unknownClientIP          = "unknown"
)

type failWindow struct {
	start    time.Time
	failures int
}

// authFailureLimiter is a fixed-window counter of failed agent authentications per
// lockout key (see Pipeline.lockoutKey). While a key is over budget every request for
// it is refused, including ones with a valid agent key, so a guesser learns nothing.
type authFailureLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	now     func() time.Time
	windows map[string]failWindow
}

func newAuthFailureLimiter(max int, window time.Duration, now func() time.Time) *authFailureLimiter {
	if now == nil {
		now = time.Now
	}
	return &authFailureLimiter{max: max, window: window, now: now, windows: make(map[string]failWindow)}
}

func clientKey(key string) string {
	if key == "" {
		return unknownClientIP
	}
	return key
}

// unregisteredAgentBucket groups every unknown agent_id from one IP, so spraying
// fresh agent IDs cannot dodge the lockout.
const unregisteredAgentBucket = "*unregistered*"

// lockoutKey scopes the lockout to (peer IP, claimed agent). All SentinelMesh agents
// reach the proxy from the API container's one IP, so an IP-wide lockout would let a
// guesser against one agent's key take every agent offline.
func (p *Pipeline) lockoutKey(req IngressRequest) string {
	agent := unregisteredAgentBucket
	if req.Declared != nil {
		if _, ok := p.pol.Agents[req.Declared.AgentID]; ok {
			agent = req.Declared.AgentID
		}
	}
	return clientKey(req.ClientIP) + "|" + agent
}

// lockedOut reports whether this request's lockout key is over its failure budget.
func (p *Pipeline) lockedOut(req IngressRequest) bool {
	return p.agentKeys != nil && p.authFailures.locked(p.lockoutKey(req))
}

func (l *authFailureLimiter) locked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.windows[clientKey(ip)]
	return ok && l.now().Sub(w.start) < l.window && w.failures >= l.max
}

func (l *authFailureLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := clientKey(ip)
	now := l.now()
	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= l.window {
		if !ok {
			l.makeRoomLocked(now)
		}
		w = failWindow{start: now}
	}
	w.failures++
	l.windows[key] = w
}

// makeRoomLocked drops expired windows, then the oldest one if still at the cap.
func (l *authFailureLimiter) makeRoomLocked(now time.Time) {
	if len(l.windows) < maxTrackedAuthIPs {
		return
	}
	oldestKey, oldest := "", now
	for k, w := range l.windows {
		if now.Sub(w.start) >= l.window {
			delete(l.windows, k)
			continue
		}
		if w.start.Before(oldest) {
			oldestKey, oldest = k, w.start
		}
	}
	if len(l.windows) >= maxTrackedAuthIPs && oldestKey != "" {
		delete(l.windows, oldestKey)
	}
}

func (l *authFailureLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.windows)
}

// WithAuthFailureLimit overrides the per-IP lockout for failed agent authentication
// (default: DefaultAuthFailuresPerWindow per DefaultAuthFailureWindow). now may be nil.
func WithAuthFailureLimit(maxFailures int, window time.Duration, now func() time.Time) Option {
	return func(p *Pipeline) {
		p.authFailures = newAuthFailureLimiter(maxFailures, window, now)
	}
}

func authRateLimitedDeny() *policy.RuleResult {
	return identityDeny(ruleAgentAuthRateLimited, "too many failed agent authentications; try again later.")
}
