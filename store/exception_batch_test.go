package store

import (
	"errors"
	"sync"
	"testing"
	"time"

	"accesssim/policy"
)

// batchTuples are three tuples the base document denies via the wildcard
// base-deny rule only.
var batchTuples = []policy.Tuple{
	{Role: "editor", Resource: "doc", Action: "read"}, // == deniedTuple
	{Role: "base", Resource: "doc", Action: "read"},
	{Role: "viewer", Resource: "doc", Action: "write"},
}

func batchReq(tuples []policy.Tuple, ttl int) ExceptionBatchRequest {
	return ExceptionBatchRequest{
		Tuples:            tuples,
		PublishedRevision: 1,
		TTLMinutes:        ttl,
		Reason:            "drill batch",
	}
}

// activeBatchIDs returns the member ids of every batch marked active.
func activeBatchIDs(t *testing.T, st *Store) map[string]bool {
	t.Helper()
	_, _, batches := st.ExceptionBatches()
	ids := map[string]bool{}
	for _, b := range batches {
		if !b.Active {
			continue
		}
		for _, m := range b.Members {
			ids[m.ID] = true
		}
	}
	return ids
}

// matrixExceptionIDs returns the ids of exceptions visible on the
// published decision matrix.
func matrixExceptionIDs(t *testing.T, st *Store) map[string]bool {
	t.Helper()
	_, rows, err := st.Decisions("published")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range rows {
		if r.Evidence.ExceptionID != "" {
			ids[r.Evidence.ExceptionID] = true
		}
	}
	return ids
}

func listedIDs(t *testing.T, st *Store) map[string]bool {
	t.Helper()
	_, _, listed, err := st.ListExceptions()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, ex := range listed {
		ids[ex.ID] = true
	}
	return ids
}

func equalIDSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if !b[id] {
			return false
		}
	}
	return true
}

// assertViewsConsistent checks the core invariant: the batch list, the
// single-exception list and the published matrix describe exactly the
// same effective exceptions.
func assertViewsConsistent(t *testing.T, st *Store) {
	t.Helper()
	active := activeBatchIDs(t, st)
	listed := listedIDs(t, st)
	matrix := matrixExceptionIDs(t, st)
	if !equalIDSet(active, listed) || !equalIDSet(listed, matrix) {
		t.Fatalf("views disagree: activeBatch=%v listed=%v matrix=%v", active, listed, matrix)
	}
}

// TestExceptionBatchCreateAtomic: if ANY member of the batch is invalid,
// the whole batch is rejected and no partial state exists anywhere —
// no exceptions, no batch record, no matrix override.
func TestExceptionBatchCreateAtomic(t *testing.T) {
	cases := []struct {
		name   string
		tuples []policy.Tuple
		want   error
	}{
		{"last tuple currently allowed", []policy.Tuple{
			batchTuples[0], batchTuples[1], allowedTuple,
		}, ErrTupleNotDenied},
		{"last tuple out of domain", []policy.Tuple{
			batchTuples[0], batchTuples[1], {Role: "ghost", Resource: "doc", Action: "read"},
		}, ErrInvalidException},
		{"duplicate inside batch", []policy.Tuple{
			batchTuples[0], batchTuples[1], batchTuples[0],
		}, ErrInvalidException},
		{"empty tuple fields", []policy.Tuple{
			batchTuples[0], {},
		}, ErrInvalidException},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := newClockStore(t)
			_, err := st.CreateExceptionBatch(batchReq(tc.tuples, 10))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if n := len(mustList(st)); n != 0 {
				t.Fatalf("partial exceptions leaked: %d", n)
			}
			_, _, batches := st.ExceptionBatches()
			if len(batches) != 0 {
				t.Fatalf("phantom batch recorded: %+v", batches)
			}
			if ids := matrixExceptionIDs(t, st); len(ids) != 0 {
				t.Fatalf("matrix shows overrides without a batch: %v", ids)
			}
		})
	}

	// A batch overlapping an existing live exception is rejected whole,
	// and the pre-existing exception is the only one left standing.
	st, _ := newClockStore(t)
	if _, err := st.CreateEmergencyException(&CreateExceptionRequest{
		Tuple: batchTuples[1], Reason: "solo", TTLMinutes: 10, PublishedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := st.CreateExceptionBatch(batchReq(batchTuples, 10))
	if !errors.Is(err, ErrExceptionExists) {
		t.Fatalf("err = %v, want ErrExceptionExists", err)
	}
	listed := mustList(st)
	if len(listed) != 1 || listed[0].Reason != "solo" {
		t.Fatalf("listed = %+v, want only the pre-existing solo exception", listed)
	}
	_, _, batches := st.ExceptionBatches()
	if len(batches) != 0 {
		t.Fatalf("rejected batch was recorded: %+v", batches)
	}

	// Batch-level validation: bad sizes, ttl, reason, revision.
	st, _ = newClockStore(t)
	for _, req := range []ExceptionBatchRequest{
		batchReq(nil, 10),
		batchReq(make([]policy.Tuple, 33), 10),
		batchReq(batchTuples, 0),
		batchReq(batchTuples, 61),
		{Tuples: batchTuples, PublishedRevision: 1, TTLMinutes: 10, Reason: "  "},
		{Tuples: batchTuples, PublishedRevision: 0, TTLMinutes: 10, Reason: "x"},
	} {
		if _, err := st.CreateExceptionBatch(req); !errors.Is(err, ErrInvalidException) {
			t.Fatalf("req %+v err = %v, want ErrInvalidException", req, err)
		}
	}
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("invalid requests leaked exceptions: %d", n)
	}
}

// TestExceptionBatchCreateSuccess: one atomic create makes the batch
// visible in every view with one shared expiry, and each matrix row
// keeps the original deny evidence next to the exception identity.
func TestExceptionBatchCreateSuccess(t *testing.T) {
	st, c := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(batchTuples, 5))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if batch.ID == "" || !batch.Active || batch.PublishedRevision != 1 {
		t.Fatalf("batch = %+v, want id, active, pinned to p1", batch)
	}
	if len(batch.Members) != len(batchTuples) {
		t.Fatalf("members = %d, want %d", len(batch.Members), len(batchTuples))
	}
	wantExpiry := c.t.Add(5 * time.Minute)
	seenIDs := map[string]bool{}
	for i, m := range batch.Members {
		if m.Tuple != batchTuples[i] {
			t.Fatalf("member %d tuple = %v, want %v", i, m.Tuple, batchTuples[i])
		}
		if !m.ExpiresAt.Equal(wantExpiry) || !m.CreatedAt.Equal(c.t) {
			t.Fatalf("member %d times = %v/%v, want shared %v/%v",
				i, m.CreatedAt, m.ExpiresAt, c.t, wantExpiry)
		}
		if m.PublishedRevision != 1 || seenIDs[m.ID] {
			t.Fatalf("member %d = %+v, want p1 pin and unique id", i, m)
		}
		seenIDs[m.ID] = true
	}

	// Matrix: temporary allow + original deny evidence + identity.
	_, rows, _ := st.Decisions("published")
	for _, tup := range batchTuples {
		r := findRow(rows, tup)
		if r.Evidence.Decision != "allow" ||
			r.Evidence.Reason != policy.ReasonEmergencyAllow ||
			r.Evidence.ExceptionID == "" || r.Exception == nil ||
			r.Evidence.OriginalReason != policy.ReasonSingleWinner ||
			r.Evidence.Winners[0].RuleID != "base-deny" {
			t.Fatalf("matrix row for %v = %+v, want emergency allow with deny evidence", tup, r)
		}
	}
	// Draft stays rule-only.
	_, draftRows, _ := st.Decisions("draft")
	for _, tup := range batchTuples {
		if r := findRow(draftRows, tup); r.Evidence.Decision != "deny" || r.Exception != nil {
			t.Fatalf("draft row for %v = %+v, exceptions must not touch draft", tup, r)
		}
	}

	// Batch list: one active batch whose members match the create result.
	rev, _, batches := st.ExceptionBatches()
	if rev != 1 || len(batches) != 1 || !batches[0].Active || batches[0].ID != batch.ID {
		t.Fatalf("batches = %+v (rev %d), want one active batch %s", batches, rev, batch.ID)
	}
	if len(batches[0].Members) != len(batchTuples) {
		t.Fatalf("listed batch members = %d", len(batches[0].Members))
	}

	assertViewsConsistent(t, st)
}

// TestExceptionBatchRenewLive: renewing a live batch extends every
// member uniformly from the renewal moment, and every view keeps
// describing the same set.
func TestExceptionBatchRenewLive(t *testing.T) {
	st, c := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(batchTuples, 5))
	if err != nil {
		t.Fatal(err)
	}
	c.advance(3 * time.Minute)

	renewed, err := st.RenewExceptionBatch(batch.ID, 10, 1)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !renewed.Active || renewed.ID != batch.ID || renewed.PublishedRevision != 1 {
		t.Fatalf("renewed = %+v", renewed)
	}
	want := c.t.Add(10 * time.Minute)
	for _, m := range renewed.Members {
		if !m.ExpiresAt.Equal(want) {
			t.Fatalf("member %s expires %v, want uniform %v", m.ID, m.ExpiresAt, want)
		}
	}
	// The single-exception list sees the same new expiry.
	_, _, listed, _ := st.ListExceptions()
	for _, ex := range listed {
		if !ex.ExpiresAt.Equal(want) {
			t.Fatalf("listed %s expires %v, want %v", ex.ID, ex.ExpiresAt, want)
		}
	}
	assertViewsConsistent(t, st)

	// Renewal is repeatable while the batch stays live.
	c.advance(9 * time.Minute)
	if _, err := st.RenewExceptionBatch(batch.ID, 1, 1); err != nil {
		t.Fatalf("second renew: %v", err)
	}
	assertViewsConsistent(t, st)
}

// TestExceptionBatchRenewExpiredIsPermanent: once the batch lapses, its
// members are pruned and can never be revived — renewal fails with
// ErrExceptionBatchExpired, deterministically, forever.
func TestExceptionBatchRenewExpiredIsPermanent(t *testing.T) {
	st, c := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(batchTuples, 5))
	if err != nil {
		t.Fatal(err)
	}
	c.advance(5 * time.Minute) // exactly at expiry: members are gone

	_, err = st.RenewExceptionBatch(batch.ID, 10, 1)
	if !errors.Is(err, ErrExceptionBatchExpired) {
		t.Fatalf("renew err = %v, want ErrExceptionBatchExpired", err)
	}
	// Members were NOT resurrected.
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("expired members revived: %d listed", n)
	}
	_, rows, _ := st.Decisions("published")
	for _, tup := range batchTuples {
		if r := findRow(rows, tup); r.Evidence.Decision != "deny" || r.Exception != nil {
			t.Fatalf("row for %v = %+v, want plain deny after expiry", tup, r)
		}
	}
	// The terminated batch stays queryable but inactive...
	_, _, batches := st.ExceptionBatches()
	if len(batches) != 1 || batches[0].Active || len(batches[0].Members) != len(batchTuples) {
		t.Fatalf("batches = %+v, want one terminated batch with full membership", batches)
	}
	// ...and no amount of retrying brings it back.
	c.advance(time.Minute)
	if _, err := st.RenewExceptionBatch(batch.ID, 10, 1); !errors.Is(err, ErrExceptionBatchExpired) {
		t.Fatalf("second renew err = %v, want ErrExceptionBatchExpired", err)
	}
	assertViewsConsistent(t, st)
}

// TestExceptionBatchRenewAfterPublish: a publish terminates the batch
// permanently. Renewal fails even when the client presents the NEW
// published revision — old members can never attach to it.
func TestExceptionBatchRenewAfterPublish(t *testing.T) {
	st, _ := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(batchTuples, 30))
	if err != nil {
		t.Fatal(err)
	}

	// Publish a new revision (add an unrelated allow rule).
	draft := baseDoc()
	draft.Rules = append(draft.Rules, policy.Rule{
		ID: "viewer-billing", Role: "viewer", Resource: "billing", Action: "read",
		Priority: 50, Effect: policy.EffectAllow,
	})
	if _, err := st.SaveDraft(draft); err != nil {
		t.Fatal(err)
	}
	sum, dr, pr, err := st.Preview()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Publish(dr, pr, sum); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Renewal stamped with the OLD revision: late request.
	if _, err := st.RenewExceptionBatch(batch.ID, 10, 1); !errors.Is(err, ErrExceptionRevisionMoved) {
		t.Fatalf("renew with old revision err = %v, want ErrExceptionRevisionMoved", err)
	}
	// Renewal stamped with the NEW revision: the batch is pinned to the
	// old one, so it is terminated — it must not attach to p2.
	if _, err := st.RenewExceptionBatch(batch.ID, 10, 2); !errors.Is(err, ErrExceptionRevisionMoved) {
		t.Fatalf("renew with new revision err = %v, want ErrExceptionRevisionMoved", err)
	}

	// Nothing was revived or re-pinned.
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("members revived after publish: %d listed", n)
	}
	rev, rows, _ := st.Decisions("published")
	if rev != 2 {
		t.Fatalf("published revision = %d, want 2", rev)
	}
	for _, tup := range batchTuples {
		r := findRow(rows, tup)
		if r.Evidence.ExceptionID != "" || r.Exception != nil {
			t.Fatalf("stale batch member attached to p2: %+v", r)
		}
	}
	_, _, batches := st.ExceptionBatches()
	if len(batches) != 1 || batches[0].Active || batches[0].PublishedRevision != 1 {
		t.Fatalf("batches = %+v, want one terminated batch still pinned to p1", batches)
	}
	assertViewsConsistent(t, st)
}

// TestExceptionBatchRenewValidation covers not-found batches, TTL bounds
// and stale request revisions.
func TestExceptionBatchRenewValidation(t *testing.T) {
	st, c := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(batchTuples, 30))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RenewExceptionBatch("batch-nope", 10, 1); !errors.Is(err, ErrExceptionBatchNotFound) {
		t.Fatalf("unknown id err = %v, want ErrExceptionBatchNotFound", err)
	}
	for _, m := range []int{0, -1, 61} {
		if _, err := st.RenewExceptionBatch(batch.ID, m, 1); !errors.Is(err, ErrInvalidException) {
			t.Fatalf("minutes %d err = %v, want ErrInvalidException", m, err)
		}
	}
	if _, err := st.RenewExceptionBatch(batch.ID, 10, 42); !errors.Is(err, ErrExceptionRevisionMoved) {
		t.Fatalf("stale revision err = %v, want ErrExceptionRevisionMoved", err)
	}
	// Failed renewals changed nothing.
	_, _, listed, _ := st.ListExceptions()
	for _, ex := range listed {
		if !ex.ExpiresAt.Equal(c.t.Add(30 * time.Minute)) {
			t.Fatalf("failed renewal moved expiry of %s to %v", ex.ID, ex.ExpiresAt)
		}
	}
}

// TestConcurrentBatchRenewAndRead hammers renewal, batch listing, the
// exception list and the matrix concurrently (run with -race): every
// view must always agree on the effective set, and no mixed state may
// appear.
func TestConcurrentBatchRenewAndRead(t *testing.T) {
	st, c := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(batchTuples, 60))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(3)
	go func() { // renewer
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := st.RenewExceptionBatch(batch.ID, 60, 1); err != nil {
				t.Errorf("renew: %v", err)
				return
			}
		}
	}()
	go func() { // batch list reader
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rev, _, batches := st.ExceptionBatches()
			if rev != 1 || len(batches) != 1 {
				t.Errorf("batches rev=%d n=%d, want 1 batch at p1", rev, len(batches))
				return
			}
			if !batches[0].Active || len(batches[0].Members) != len(batchTuples) {
				t.Errorf("batch view incoherent: %+v", batches[0])
				return
			}
		}
	}()
	go func() { // matrix reader checking the no-mixed-state invariant
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, rows, err := st.Decisions("published")
			if err != nil {
				t.Errorf("decisions: %v", err)
				return
			}
			for _, r := range rows {
				if (r.Evidence.ExceptionID != "") != (r.Exception != nil) {
					t.Errorf("mixed state on %+v", r.Tuple)
					return
				}
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
	_ = c
	assertViewsConsistent(t, st)
}
