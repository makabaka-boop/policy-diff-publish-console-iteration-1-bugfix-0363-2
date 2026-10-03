package store

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"accesssim/policy"
)

// MaxExceptionBatchSize bounds one batch. The finite domain caps at 384
// tuples and a drill batch is meant to be a handful of exact tuples.
const MaxExceptionBatchSize = 32

var (
	// ErrExceptionBatchNotFound is returned when no batch (live or
	// terminated) carries the requested id.
	ErrExceptionBatchNotFound = errors.New("unknown exception batch id")
	// ErrExceptionBatchExpired is returned when a renewal targets a batch
	// whose members are no longer all live exceptions. Expired members
	// are never resurrected: a terminated batch stays terminated, and
	// the tuples need a freshly adjudicated batch instead.
	ErrExceptionBatchExpired = errors.New("exception batch has expired: terminated batches cannot be renewed, create a new batch against the current revision")
)

// ExceptionBatch groups exact-tuple exceptions that share one published
// revision, one reason and one TTL. A batch is effective exactly while
// ALL of its members are live exceptions pinned to the current published
// revision: expiry terminates every member at the same instant, and a
// publish or reset invalidates the whole batch permanently — it can
// never attach to a newer revision.
type ExceptionBatch struct {
	ID                string                `json:"id"`
	PublishedRevision int                   `json:"publishedRevision"`
	Members           []*EmergencyException `json:"members"`
	Reason            string                `json:"reason"`
	// seq orders batches by creation for deterministic listings.
	seq int64
}

type ExceptionBatchRequest struct {
	Tuples            []policy.Tuple `json:"tuples"`
	PublishedRevision int            `json:"publishedRevision"`
	TTLMinutes        int            `json:"ttlMinutes"`
	Reason            string         `json:"reason"`
}

// CreateExceptionBatch creates one exception per tuple, all pinned to
// the same published revision with the same TTL — atomically: every
// tuple is validated and re-adjudicated BEFORE any exception is
// recorded, so a single invalid tuple rejects the whole request and
// leaves neither exceptions nor a batch record behind.
func (s *Store) CreateExceptionBatch(req ExceptionBatchRequest) (*ExceptionBatch, error) {
	if len(req.Tuples) == 0 || len(req.Tuples) > MaxExceptionBatchSize {
		return nil, fmt.Errorf("%w: a batch needs between 1 and %d tuples",
			ErrInvalidException, MaxExceptionBatchSize)
	}

	// Validate the shared fields and every tuple up front, reusing the
	// single-exception rules, and reject duplicate tuples inside the
	// request itself (the second occurrence would otherwise collide with
	// the first one's exception).
	seen := make(map[policy.Tuple]bool, len(req.Tuples))
	validated := make([]CreateExceptionRequest, 0, len(req.Tuples))
	var ttl time.Duration
	for _, tuple := range req.Tuples {
		if seen[tuple] {
			return nil, fmt.Errorf("%w: tuple %s/%s/%s appears twice in the batch",
				ErrInvalidException, tuple.Role, tuple.Resource, tuple.Action)
		}
		seen[tuple] = true
		member := &CreateExceptionRequest{
			Tuple:             tuple,
			Reason:            req.Reason,
			TTLMinutes:        req.TTLMinutes,
			PublishedRevision: req.PublishedRevision,
		}
		memberTTL, err := s.validateExceptionRequest(member)
		if err != nil {
			return nil, err
		}
		ttl = memberTTL
		validated = append(validated, *member)
	}
	reason := validated[0].Reason // trimmed by validation

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	live := s.pruneExceptionsLocked(now)

	// Late request: the matrix the admin saw belongs to an old revision.
	if req.PublishedRevision != s.published.Revision {
		return nil, ErrExceptionRevisionMoved
	}
	eng, err := policy.NewEngine(s.published.Document)
	if err != nil {
		return nil, err
	}

	// Phase 1: re-adjudicate EVERY tuple against the current published
	// revision. Nothing is recorded in this phase, so any rejection is
	// wholesale — no earlier tuple can stay released behind a failed
	// batch, and no half-recorded batch can appear in the listings.
	for _, member := range validated {
		if _, err := checkExceptionTuple(member.Tuple, live, eng); err != nil {
			return nil, err
		}
	}

	// Phase 2: every check passed — record all members and the batch in
	// the same critical section.
	batch := &ExceptionBatch{
		PublishedRevision: s.published.Revision,
		Reason:            reason,
	}
	for _, member := range validated {
		batch.Members = append(batch.Members, s.recordExceptionLocked(member.Tuple, reason, ttl, now))
	}
	s.batchSeq++
	batch.ID = fmt.Sprintf("batch-%d", s.batchSeq)
	batch.seq = s.batchSeq
	if s.batches == nil {
		s.batches = map[string]*ExceptionBatch{}
	}
	s.batches[batch.ID] = batch
	return copyExceptionBatch(batch), nil
}

// RenewExceptionBatch extends every member of a still-effective batch to
// now+minutes. Renewal is only possible while the batch is effective:
//
//   - the caller's publishedRevision must be the current one (a late
//     request is rejected exactly like a late single create);
//   - the batch must still be pinned to the current published revision —
//     a publish invalidates the whole batch permanently and it can never
//     attach to a newer revision;
//   - every member must still be a live exception — expired members are
//     never resurrected; a terminated batch stays terminated.
//
// Only then are the live members extended, all in one critical section,
// so the batch list, the exception list and the decision matrix always
// describe the same effective scope.
func (s *Store) RenewExceptionBatch(id string, minutes, revision int) (*ExceptionBatch, error) {
	if minutes < MinExceptionTTLMinutes || minutes > MaxExceptionTTLMinutes {
		return nil, fmt.Errorf("%w: minutes must be within [%d,%d]",
			ErrInvalidException, MinExceptionTTLMinutes, MaxExceptionTTLMinutes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	live := s.pruneExceptionsLocked(now)

	if revision != s.published.Revision {
		return nil, ErrExceptionRevisionMoved
	}
	batch := s.batches[id]
	if batch == nil {
		return nil, ErrExceptionBatchNotFound
	}
	if batch.PublishedRevision != s.published.Revision {
		// A publish moved the revision on: the old batch is permanently
		// invalid and must never attach to the new revision.
		return nil, ErrExceptionRevisionMoved
	}
	if !batchEffectiveLocked(batch, live) {
		return nil, ErrExceptionBatchExpired
	}
	for _, ex := range batch.Members {
		ex.ExpiresAt = now.Add(time.Duration(minutes) * time.Minute)
	}
	return copyExceptionBatch(batch), nil
}

// ExceptionBatches lists the currently effective batches — exactly those
// whose every member is still a live exception pinned to the current
// published revision. Expired and publish-invalidated batches are
// filtered out under the same lazy-expiry adjudication as the exception
// list and the decision matrix, so all three views (plus the original
// deny evidence) describe the same effective scope.
func (s *Store) ExceptionBatches() []ExceptionBatch {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	live := s.pruneExceptionsLocked(now)
	out := []ExceptionBatch{}
	for _, batch := range s.batches {
		if batch.PublishedRevision != s.published.Revision || !batchEffectiveLocked(batch, live) {
			continue
		}
		out = append(out, *copyExceptionBatch(batch))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

// batchEffectiveLocked reports whether every member of the batch is one
// of the currently live exceptions. Members share one expiry instant, so
// this is all-or-nothing by construction. Callers must hold s.mu.
func batchEffectiveLocked(batch *ExceptionBatch, live []*EmergencyException) bool {
	if len(batch.Members) == 0 {
		return false
	}
	liveByID := make(map[string]bool, len(live))
	for _, ex := range live {
		liveByID[ex.ID] = true
	}
	for _, ex := range batch.Members {
		if !liveByID[ex.ID] {
			return false
		}
	}
	return true
}

// copyExceptionBatch deep-copies a batch so callers can serialize it
// without holding the lock while a concurrent renewal extends member
// expiries. Callers must hold s.mu.
func copyExceptionBatch(b *ExceptionBatch) *ExceptionBatch {
	cp := &ExceptionBatch{
		ID:                b.ID,
		PublishedRevision: b.PublishedRevision,
		Reason:            b.Reason,
		seq:               b.seq,
	}
	cp.Members = make([]*EmergencyException, 0, len(b.Members))
	for _, m := range b.Members {
		m := *m
		cp.Members = append(cp.Members, &m)
	}
	return cp
}
