package store

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"accesssim/policy"
)

// Sentinel errors for the batch lifecycle, mapped to HTTP statuses by
// the API layer.
var (
	// ErrExceptionBatchNotFound: no batch with that id was ever recorded.
	ErrExceptionBatchNotFound = errors.New("no such exception batch")
	// ErrExceptionBatchExpired: at least one member has already expired
	// (or been purged), so the batch is terminated. Expired members are
	// never revived and a terminated batch can never be re-enabled —
	// the only way forward is a freshly adjudicated new batch.
	ErrExceptionBatchExpired = errors.New("exception batch has terminated members: expired exceptions are never revived, create a new batch")
)

// maxExceptionBatchSize bounds one drill batch.
const maxExceptionBatchSize = 32

// ExceptionBatch groups same-revision, same-TTL exceptions created
// atomically for one drill. The batch record is kept after termination
// (member expiry or a publish) so its full membership stays auditable;
// Active marks whether it can still take effect.
type ExceptionBatch struct {
	ID                string                `json:"id"`
	PublishedRevision int                   `json:"publishedRevision"`
	Members           []*EmergencyException `json:"members"`
	Reason            string                `json:"reason"`
	// Active is a derived, read-time marker: true only while the batch
	// is pinned to the current published revision AND every member is
	// still live. It is filled on every outbound copy; the stored record
	// never carries it, so a terminated batch can never masquerade as
	// renewable.
	Active bool `json:"active"`
}

type ExceptionBatchRequest struct {
	Tuples            []policy.Tuple `json:"tuples"`
	PublishedRevision int            `json:"publishedRevision"`
	TTLMinutes        int            `json:"ttlMinutes"`
	Reason            string         `json:"reason"`
}

// CreateExceptionBatch records a whole batch atomically: every tuple is
// validated and re-adjudicated against the CURRENT published revision
// inside one critical section, and only when ALL of them pass is any
// exception recorded. A batch therefore either exists in full — in the
// batch registry, the exception list and the published matrix alike —
// or leaves no partial state at all.
//
// All members share one clock reading, one TTL, one reason and one
// pinned revision, so the batch lives and expires as a unit.
func (s *Store) CreateExceptionBatch(req ExceptionBatchRequest) (*ExceptionBatch, error) {
	if len(req.Tuples) == 0 || len(req.Tuples) > maxExceptionBatchSize {
		return nil, fmt.Errorf("%w: a batch needs 1-%d tuples", ErrInvalidException, maxExceptionBatchSize)
	}
	// Validate every member up front with the exact same rules as the
	// single-exception endpoint. Pure request validation: no store state
	// is touched in this phase.
	memberReqs := make([]*CreateExceptionRequest, 0, len(req.Tuples))
	var ttl time.Duration
	for _, tuple := range req.Tuples {
		mr := &CreateExceptionRequest{
			Tuple:             tuple,
			Reason:            req.Reason,
			TTLMinutes:        req.TTLMinutes,
			PublishedRevision: req.PublishedRevision,
		}
		d, err := s.validateExceptionRequest(mr)
		if err != nil {
			return nil, err
		}
		ttl = d
		memberReqs = append(memberReqs, mr)
	}
	reason := memberReqs[0].Reason // trimmed, identical across members

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

	// Phase 1: re-adjudicate EVERY tuple inside the same critical
	// section. Any failure rejects the whole batch before a single
	// exception is recorded.
	seen := make(map[policy.Tuple]bool, len(memberReqs))
	for _, mr := range memberReqs {
		if seen[mr.Tuple] {
			return nil, fmt.Errorf("%w: duplicate tuple %s/%s/%s inside the batch",
				ErrInvalidException, mr.Tuple.Role, mr.Tuple.Resource, mr.Tuple.Action)
		}
		seen[mr.Tuple] = true
		if _, err := s.validateTupleLocked(eng, live, mr.Tuple); err != nil {
			return nil, err
		}
	}

	// Phase 2: every tuple passed — record all members under one shared
	// clock reading, then register the batch. Both happen in the same
	// critical section, so no reader can observe members without their
	// batch (or vice versa).
	batch := &ExceptionBatch{
		PublishedRevision: s.published.Revision,
		Reason:            reason,
	}
	for _, mr := range memberReqs {
		batch.Members = append(batch.Members, s.addExceptionLocked(mr.Tuple, mr.Reason, ttl, now))
	}
	batch.ID = fmt.Sprintf("batch-%d", s.exceptionSeq)
	s.batches[batch.ID] = batch

	out := cloneExceptionBatch(batch)
	out.Active = true
	return out, nil
}

// RenewExceptionBatch extends a still-live batch uniformly: every member
// gets a fresh expiry of `minutes` from now.
//
// Renewal is only possible while the batch is genuinely in force:
//   - the request must carry the current published revision (a late
//     request is refused, exactly like a late create);
//   - the batch must still be pinned to that revision — a publish or
//     reset terminates every batch of the old revision permanently, and
//     renewal can never attach old members to the new revision;
//   - every member must still be live — an expired member is gone for
//     good, so a batch with a terminated member can never be renewed
//     again (ErrExceptionBatchExpired).
//
// Because terminated batches fail these checks deterministically, a
// successful renewal always describes a still-effective batch, never a
// re-enabled terminated one.
func (s *Store) RenewExceptionBatch(id string, minutes, revision int) (*ExceptionBatch, error) {
	if minutes < MinExceptionTTLMinutes || minutes > MaxExceptionTTLMinutes {
		return nil, fmt.Errorf("%w: minutes must be within [%d,%d]",
			ErrInvalidException, MinExceptionTTLMinutes, MaxExceptionTTLMinutes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	batch := s.batches[id]
	if batch == nil {
		return nil, ErrExceptionBatchNotFound
	}
	// Late request: the client is looking at an old published revision.
	if revision != s.published.Revision {
		return nil, ErrExceptionRevisionMoved
	}
	// The batch itself belongs to a superseded revision: a publish
	// terminated it permanently, even if the client already knows the
	// new revision number.
	if batch.PublishedRevision != s.published.Revision {
		return nil, ErrExceptionRevisionMoved
	}

	now := s.now()
	live := s.pruneExceptionsLocked(now)
	if !batch.allMembersLive(liveSet(live)) {
		return nil, ErrExceptionBatchExpired
	}
	for _, ex := range batch.Members {
		ex.ExpiresAt = now.Add(time.Duration(minutes) * time.Minute)
	}
	out := cloneExceptionBatch(batch)
	out.Active = true
	return out, nil
}

// ExceptionBatches lists every recorded batch — live and terminated —
// as deep copies, together with the published revision and the
// adjudication clock reading of the same critical section. Each batch
// carries its derived Active marker, so the batch list, the single
// exception list and the published matrix all describe the same
// effective scope.
func (s *Store) ExceptionBatches() (int, time.Time, []ExceptionBatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	live := liveSet(s.pruneExceptionsLocked(now))
	out := make([]ExceptionBatch, 0, len(s.batches))
	for _, batch := range s.batches {
		cp := cloneExceptionBatch(batch)
		cp.Active = batch.PublishedRevision == s.published.Revision && batch.allMembersLive(live)
		out = append(out, *cp)
	}
	// Deterministic order: creation time, then id.
	sort.Slice(out, func(i, j int) bool {
		ci, cj := out[i].Members[0].CreatedAt, out[j].Members[0].CreatedAt
		if !ci.Equal(cj) {
			return ci.Before(cj)
		}
		return out[i].ID < out[j].ID
	})
	return s.published.Revision, now, out
}

// allMembersLive reports whether every member is in the live set.
func (b *ExceptionBatch) allMembersLive(live map[string]bool) bool {
	for _, m := range b.Members {
		if !live[m.ID] {
			return false
		}
	}
	return true
}

func liveSet(live []*EmergencyException) map[string]bool {
	set := make(map[string]bool, len(live))
	for _, ex := range live {
		set[ex.ID] = true
	}
	return set
}

// cloneExceptionBatch deep-copies a batch (members included) so callers
// can serialize or mutate the result without touching store state.
func cloneExceptionBatch(b *ExceptionBatch) *ExceptionBatch {
	cp := &ExceptionBatch{
		ID:                b.ID,
		PublishedRevision: b.PublishedRevision,
		Reason:            b.Reason,
		Active:            b.Active,
		Members:           make([]*EmergencyException, 0, len(b.Members)),
	}
	for _, m := range b.Members {
		mc := *m
		cp.Members = append(cp.Members, &mc)
	}
	return cp
}
