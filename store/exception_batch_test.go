package store

import (
	"errors"
	"sync"
	"testing"
	"time"

	"accesssim/policy"
)

// More tuples denied by baseDoc's wildcard base-deny rule.
var (
	deniedTuple2 = policy.Tuple{Role: "base", Resource: "billing", Action: "write"}
	deniedTuple3 = policy.Tuple{Role: "viewer", Resource: "billing", Action: "write"}
)

func batchReq(tuples ...policy.Tuple) ExceptionBatchRequest {
	return ExceptionBatchRequest{
		Tuples:            tuples,
		PublishedRevision: 1,
		TTLMinutes:        5,
		Reason:            "drill batch",
	}
}

func liveBatchIDs(st *Store) []string {
	var ids []string
	for _, b := range st.ExceptionBatches() {
		ids = append(ids, b.ID)
	}
	return ids
}

// TestBatchCreateAllOrNothing: a batch is recorded wholesale or not at
// all. When any member is rejected, no earlier member may stay released
// and no half-recorded batch may appear in the listings.
func TestBatchCreateAllOrNothing(t *testing.T) {
	st, c := newClockStore(t)

	// Happy path: two denied tuples become one batch with one expiry.
	batch, err := st.CreateExceptionBatch(batchReq(deniedTuple, deniedTuple2))
	if err != nil {
		t.Fatalf("create batch: %v", err)
	}
	if batch.ID == "" || batch.PublishedRevision != 1 || len(batch.Members) != 2 {
		t.Fatalf("batch = %+v, want id, pin 1 and 2 members", batch)
	}
	wantExpiry := c.t.Add(5 * time.Minute)
	for _, m := range batch.Members {
		if !m.ExpiresAt.Equal(wantExpiry) || m.PublishedRevision != 1 {
			t.Fatalf("member = %+v, want shared expiry %v pinned to p1", m, wantExpiry)
		}
	}
	if got := liveBatchIDs(st); len(got) != 1 || got[0] != batch.ID {
		t.Fatalf("listed batches = %v, want [%s]", got, batch.ID)
	}
	if n := len(mustList(st)); n != 2 {
		t.Fatalf("live exceptions = %d, want 2", n)
	}

	// Both tuples are temporarily allowed on the published matrix with
	// the original deny evidence attached; the draft stays rule-only.
	_, pubRows, _ := st.Decisions("published")
	for _, tup := range []policy.Tuple{deniedTuple, deniedTuple2} {
		r := findRow(pubRows, tup)
		if r.Evidence.Decision != "allow" || r.Evidence.ExceptionID == "" || r.Exception == nil {
			t.Fatalf("published row for %v = %+v, want emergency allow", tup, r)
		}
		if r.Evidence.Winners[0].RuleID != "base-deny" || r.Evidence.OriginalReason == "" {
			t.Fatalf("published row for %v lost original deny evidence: %+v", tup, r.Evidence)
		}
	}
	_, draftRows, _ := st.Decisions("draft")
	if r := findRow(draftRows, deniedTuple); r.Evidence.Decision != "deny" || r.Exception != nil {
		t.Fatalf("draft row = %+v, batch must not touch draft decisions", r)
	}

	// A batch whose LAST tuple is currently allowed must fail without
	// releasing its first tuple or recording anything.
	_, err = st.CreateExceptionBatch(batchReq(deniedTuple3, allowedTuple))
	if !errors.Is(err, ErrTupleNotDenied) {
		t.Fatalf("err = %v, want ErrTupleNotDenied", err)
	}
	assertOnlyFirstBatch(t, st, batch.ID, 2)
	assertTupleNotReleased(t, st, deniedTuple3)

	// Duplicate tuple inside the request.
	if _, err = st.CreateExceptionBatch(batchReq(deniedTuple3, deniedTuple3)); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("duplicate-in-batch err = %v, want ErrInvalidException", err)
	}
	assertOnlyFirstBatch(t, st, batch.ID, 2)
	assertTupleNotReleased(t, st, deniedTuple3)

	// Out-of-domain tuple at the tail.
	foreign := policy.Tuple{Role: "ghost", Resource: "doc", Action: "read"}
	if _, err = st.CreateExceptionBatch(batchReq(deniedTuple3, foreign)); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("foreign tuple err = %v, want ErrInvalidException", err)
	}
	assertOnlyFirstBatch(t, st, batch.ID, 2)
	assertTupleNotReleased(t, st, deniedTuple3)

	// A tuple already covered by a live single exception.
	single, err := st.CreateEmergencyException(&CreateExceptionRequest{
		Tuple: deniedTuple3, Reason: "single", TTLMinutes: 5, PublishedRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.CreateExceptionBatch(batchReq(deniedTuple3)); !errors.Is(err, ErrExceptionExists) {
		t.Fatalf("conflict err = %v, want ErrExceptionExists", err)
	}
	assertOnlyFirstBatch(t, st, batch.ID, 3)
	// The exception covering deniedTuple3 is still the single one — the
	// rejected batch did not record a second, hidden member for it.
	_, rows, _ := st.Decisions("published")
	if r := findRow(rows, deniedTuple3); r.Evidence.ExceptionID != single.Exception.ID {
		t.Fatalf("row for %v = %+v, want the single exception %s", deniedTuple3, r, single.Exception.ID)
	}

	// Size bounds: empty and oversized batches are rejected up front.
	if _, err = st.CreateExceptionBatch(batchReq()); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("empty batch err = %v, want ErrInvalidException", err)
	}
	oversized := ExceptionBatchRequest{PublishedRevision: 1, TTLMinutes: 5, Reason: "x"}
	for i := 0; i < MaxExceptionBatchSize+1; i++ {
		oversized.Tuples = append(oversized.Tuples, deniedTuple)
	}
	if _, err = st.CreateExceptionBatch(oversized); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("oversized batch err = %v, want ErrInvalidException", err)
	}
}

// assertOnlyFirstBatch verifies the all-or-nothing invariant after a
// rejected batch: exactly the first batch's two members are live, no
// extra batch was recorded, and no other tuple was released.
func assertOnlyFirstBatch(t *testing.T, st *Store, id string, wantLive int) {
	t.Helper()
	if got := liveBatchIDs(st); len(got) != 1 || got[0] != id {
		t.Fatalf("listed batches = %v, want only [%s]", got, id)
	}
	listed := mustList(st)
	if len(listed) != wantLive {
		t.Fatalf("live exceptions = %+v, want exactly %d (no partial batch state)", listed, wantLive)
	}
}

// assertTupleNotReleased verifies a rejected batch did not leave its
// would-be member released on the published matrix.
func assertTupleNotReleased(t *testing.T, st *Store, tup policy.Tuple) {
	t.Helper()
	_, rows, _ := st.Decisions("published")
	if r := findRow(rows, tup); r.Evidence.ExceptionID != "" || r.Exception != nil {
		t.Fatalf("rejected batch left %v released: %+v", tup, r)
	}
}

// TestBatchRenewExtendsLiveMembersOnly covers the renewal contract:
// a live batch renews atomically; an expired batch can never be
// resurrected, and a terminated batch stays terminated.
func TestBatchRenewExtendsLiveMembersOnly(t *testing.T) {
	st, c := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(deniedTuple, deniedTuple2))
	if err != nil {
		t.Fatal(err)
	}

	// Renewal while every member is live extends all of them to
	// now+minutes, pinned to the same revision.
	c.advance(4 * time.Minute)
	renewed, err := st.RenewExceptionBatch(batch.ID, 10, 1)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	wantExpiry := c.t.Add(10 * time.Minute)
	for _, m := range renewed.Members {
		if !m.ExpiresAt.Equal(wantExpiry) || m.PublishedRevision != 1 {
			t.Fatalf("renewed member = %+v, want expiry %v pinned to p1", m, wantExpiry)
		}
	}
	if got := liveBatchIDs(st); len(got) != 1 || got[0] != batch.ID {
		t.Fatalf("listed batches after renew = %v", got)
	}
	_, rows, _ := st.Decisions("published")
	if r := findRow(rows, deniedTuple); r.Evidence.Decision != "allow" || r.Exception == nil {
		t.Fatalf("row after renew = %+v, want still released", r)
	}

	// Renewal validation: bad TTL, unknown id, stale request revision.
	if _, err = st.RenewExceptionBatch(batch.ID, 0, 1); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("minutes 0 err = %v, want ErrInvalidException", err)
	}
	if _, err = st.RenewExceptionBatch(batch.ID, 61, 1); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("minutes 61 err = %v, want ErrInvalidException", err)
	}
	if _, err = st.RenewExceptionBatch("batch-999", 5, 1); !errors.Is(err, ErrExceptionBatchNotFound) {
		t.Fatalf("unknown id err = %v, want ErrExceptionBatchNotFound", err)
	}
	if _, err = st.RenewExceptionBatch(batch.ID, 5, 7); !errors.Is(err, ErrExceptionRevisionMoved) {
		t.Fatalf("stale revision err = %v, want ErrExceptionRevisionMoved", err)
	}

	// Let the batch expire: members vanish from the live exceptions and
	// the batch from the listing at the same adjudication instant.
	c.advance(10 * time.Minute)
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("live exceptions after expiry = %d, want 0", n)
	}
	if got := liveBatchIDs(st); len(got) != 0 {
		t.Fatalf("listed batches after expiry = %v, want none", got)
	}
	_, rows, _ = st.Decisions("published")
	if r := findRow(rows, deniedTuple); r.Evidence.Decision != "deny" || r.Exception != nil {
		t.Fatalf("row after expiry = %+v, want plain rule deny", r)
	}

	// Renewal must NOT resurrect the expired members.
	if _, err = st.RenewExceptionBatch(batch.ID, 10, 1); !errors.Is(err, ErrExceptionBatchExpired) {
		t.Fatalf("renew expired err = %v, want ErrExceptionBatchExpired", err)
	}
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("expired batch resurrected %d exceptions", n)
	}
	if got := liveBatchIDs(st); len(got) != 0 {
		t.Fatalf("terminated batch reappeared: %v", got)
	}
	_, rows, _ = st.Decisions("published")
	if r := findRow(rows, deniedTuple); r.Evidence.Decision != "deny" || r.Evidence.ExceptionID != "" {
		t.Fatalf("row after rejected renewal = %+v, want plain deny", r)
	}

	// The tuples can still get a FRESH batch, re-adjudicated against the
	// current revision, with brand-new ids.
	fresh, err := st.CreateExceptionBatch(batchReq(deniedTuple, deniedTuple2))
	if err != nil {
		t.Fatalf("fresh batch after expiry: %v", err)
	}
	if fresh.ID == batch.ID || fresh.Members[0].ID == batch.Members[0].ID {
		t.Fatal("ids reused after expiry")
	}
}

// TestBatchPublishInvalidatesPermanently: a publish drops the members
// and terminates the batch in the same critical section; the old batch
// can never be renewed onto the new revision.
func TestBatchPublishInvalidatesPermanently(t *testing.T) {
	st, _ := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(deniedTuple2, deniedTuple3))
	if err != nil {
		t.Fatal(err)
	}

	// Publish a new revision (unrelated rule; both tuples stay denied).
	draft := baseDoc()
	draft.Rules = append(draft.Rules, policy.Rule{
		ID: "editor-read", Role: "editor", Resource: "doc", Action: "read",
		Priority: 20, Effect: policy.EffectAllow,
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

	// Every view agrees: no live exceptions, no effective batches, no
	// exception identity on the matrix.
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("live exceptions after publish = %d, want 0", n)
	}
	if got := liveBatchIDs(st); len(got) != 0 {
		t.Fatalf("listed batches after publish = %v, want none", got)
	}
	_, rows, _ := st.Decisions("published")
	for _, tup := range []policy.Tuple{deniedTuple2, deniedTuple3} {
		if r := findRow(rows, tup); r.Evidence.ExceptionID != "" || r.Exception != nil {
			t.Fatalf("row for %v after publish = %+v, want no exception traces", tup, r)
		}
	}

	// Renewal stamped with the OLD revision is late; renewal stamped
	// with the NEW revision tries to attach the terminated batch to a
	// revision it was never adjudicated against. Both are rejected and
	// neither resurrects anything.
	if _, err = st.RenewExceptionBatch(batch.ID, 5, 1); !errors.Is(err, ErrExceptionRevisionMoved) {
		t.Fatalf("renew with old revision err = %v, want ErrExceptionRevisionMoved", err)
	}
	if _, err = st.RenewExceptionBatch(batch.ID, 5, 2); !errors.Is(err, ErrExceptionRevisionMoved) {
		t.Fatalf("renew onto new revision err = %v, want ErrExceptionRevisionMoved", err)
	}
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("publish-invalidated batch resurrected %d exceptions", n)
	}
	if got := liveBatchIDs(st); len(got) != 0 {
		t.Fatalf("terminated batch reappeared after publish: %v", got)
	}

	// A fresh batch against the CURRENT revision works and gets new ids.
	fresh, err := st.CreateExceptionBatch(ExceptionBatchRequest{
		Tuples:            []policy.Tuple{deniedTuple2, deniedTuple3},
		PublishedRevision: 2,
		TTLMinutes:        5,
		Reason:            "re-adjudicated",
	})
	if err != nil {
		t.Fatalf("fresh batch on p2: %v", err)
	}
	if fresh.PublishedRevision != 2 || fresh.ID == batch.ID {
		t.Fatalf("fresh batch = %+v, want new id pinned to p2", fresh)
	}
}

// TestBatchViewsStayConsistent is the cross-view invariant from the
// incident report: the batch list, the single-exception list, the
// published decisions and the original deny evidence must always
// describe the same effective scope — while live, after renewal, and
// after expiry.
func TestBatchViewsStayConsistent(t *testing.T) {
	st, c := newClockStore(t)

	// One single exception plus one batch, overlapping in time.
	single, err := st.CreateEmergencyException(&CreateExceptionRequest{
		Tuple: deniedTuple3, Reason: "single", TTLMinutes: 30, PublishedRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := st.CreateExceptionBatch(batchReq(deniedTuple, deniedTuple2))
	if err != nil {
		t.Fatal(err)
	}

	assertConsistent := func(stage string, wantLive map[string]string) {
		t.Helper()
		// wantLive maps exception id -> tuple string for every exception
		// that must be observable right now, batch member or not.
		listed := mustList(st)
		if len(listed) != len(wantLive) {
			t.Fatalf("%s: list has %d exceptions, want %d", stage, len(listed), len(wantLive))
		}
		for _, ex := range listed {
			if _, ok := wantLive[ex.ID]; !ok {
				t.Fatalf("%s: unexpected live exception %+v", stage, ex)
			}
		}
		_, rows, _ := st.Decisions("published")
		for _, r := range rows {
			key := r.Tuple.Role + "/" + r.Tuple.Resource + "/" + r.Tuple.Action
			if wantLive[r.Evidence.ExceptionID] == key {
				// A released tuple: allow + identity + object + the
				// original deny evidence, all from one adjudication.
				if r.Evidence.Decision != "allow" || r.Exception == nil ||
					r.Evidence.OriginalReason == "" || len(r.Evidence.Winners) == 0 {
					t.Fatalf("%s: incoherent released row %+v", stage, r)
				}
				delete(wantLive, r.Evidence.ExceptionID)
			} else if r.Evidence.ExceptionID != "" || r.Exception != nil {
				t.Fatalf("%s: unexpected exception traces on row %+v", stage, r)
			}
		}
		if len(wantLive) != 0 {
			t.Fatalf("%s: exceptions %v listed but missing from decisions", stage, wantLive)
		}
	}

	live := map[string]string{
		single.Exception.ID: "viewer/billing/write",
		batch.Members[0].ID: "editor/doc/read",
		batch.Members[1].ID: "base/billing/write",
	}
	assertConsistent("after create", live)

	// The batch list covers exactly the batch members — no more, no less.
	batches := st.ExceptionBatches()
	if len(batches) != 1 || len(batches[0].Members) != 2 {
		t.Fatalf("listed batches = %+v, want the one 2-member batch", batches)
	}
	for _, m := range batches[0].Members {
		if m.ID != batch.Members[0].ID && m.ID != batch.Members[1].ID {
			t.Fatalf("batch list member %s not in exception list", m.ID)
		}
	}

	// After the batch expires (single still live), every view drops
	// exactly the batch members at the same instant.
	c.advance(5 * time.Minute)
	assertConsistent("after batch expiry", map[string]string{
		single.Exception.ID: "viewer/billing/write",
	})
	if got := liveBatchIDs(st); len(got) != 0 {
		t.Fatalf("terminated batch still listed: %v", got)
	}
}

// TestConcurrentBatchRenewPublishList interleaves batch creation,
// renewal, publishing and every listing under -race and asserts the
// cross-view invariant at each observation: a listed batch is always
// fully live and pinned to the current published revision, and a
// decision row carrying an exception identity always carries the
// matching exception object — no mixed state, no resurrected members.
func TestConcurrentBatchRenewPublishList(t *testing.T) {
	st, _ := newClockStore(t)
	batch, err := st.CreateExceptionBatch(batchReq(deniedTuple, deniedTuple2))
	if err != nil {
		t.Fatal(err)
	}

	eng := mustEngine(t, baseDoc())
	sum, err := policy.BuildSummary(eng, 1, eng, 1)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { // one publish wins; the batch must never survive onto p2
		defer wg.Done()
		_, _ = st.Publish(1, 1, sum)
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			_, err := st.RenewExceptionBatch(batch.ID, 5, 1)
			switch {
			case err == nil,
				errors.Is(err, ErrExceptionRevisionMoved),
				errors.Is(err, ErrExceptionBatchExpired),
				errors.Is(err, ErrExceptionBatchNotFound):
			default:
				t.Errorf("unexpected renew error: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			rev, _, listed, err := st.ListExceptions()
			if err != nil {
				t.Errorf("list: %v", err)
				return
			}
			for _, ex := range listed {
				if ex.PublishedRevision != rev {
					t.Errorf("exception %s pinned to p%d observed under p%d", ex.ID, ex.PublishedRevision, rev)
				}
			}
			for _, b := range st.ExceptionBatches() {
				if len(b.Members) == 0 || b.PublishedRevision != rev {
					t.Errorf("listed batch %+v not pinned to current revision p%d", b, rev)
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 50 {
			rev, rows, err := st.Decisions("published")
			if err != nil {
				t.Errorf("decisions: %v", err)
				return
			}
			for _, r := range rows {
				hasID := r.Evidence.ExceptionID != ""
				hasObj := r.Exception != nil
				if hasID != hasObj {
					t.Errorf("mixed state on %+v: exceptionId=%v object=%v", r.Tuple, hasID, hasObj)
				}
				if hasObj && r.Exception.PublishedRevision != rev {
					t.Errorf("stale p%d exception observable under p%d", r.Exception.PublishedRevision, rev)
				}
			}
		}
	}()
	wg.Wait()

	// Final state: published moved to p2, so the p1 batch is terminated
	// everywhere — nothing pinned to p1 may be observable or renewable.
	if got := liveBatchIDs(st); len(got) != 0 {
		t.Fatalf("batches listed after publish: %v", got)
	}
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("exceptions live after publish: %d", n)
	}
	if _, err := st.RenewExceptionBatch(batch.ID, 5, 2); !errors.Is(err, ErrExceptionRevisionMoved) {
		t.Fatalf("renew after publish err = %v, want ErrExceptionRevisionMoved", err)
	}
	if n := len(mustList(st)); n != 0 {
		t.Fatalf("renew after publish resurrected %d exceptions", n)
	}
}
