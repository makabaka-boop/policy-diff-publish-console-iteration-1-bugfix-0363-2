package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"accesssim/policy"
)

type batchPayload struct {
	ID                string             `json:"id"`
	PublishedRevision int                `json:"publishedRevision"`
	Reason            string             `json:"reason"`
	Members           []exceptionPayload `json:"members"`
}

func createBatch(t *testing.T, base string, body any) *http.Response {
	t.Helper()
	return postJSON(t, http.MethodPost, base+"/api/exception-batches", body)
}

func mustListBatches(t *testing.T, base string) []batchPayload {
	t.Helper()
	resp, err := http.Get(base + "/api/exception-batches")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET exception-batches status %d", resp.StatusCode)
	}
	var batches []batchPayload
	if err := json.NewDecoder(resp.Body).Decode(&batches); err != nil {
		t.Fatal(err)
	}
	return batches
}

func mustListExceptions(t *testing.T, base string) []exceptionPayload {
	t.Helper()
	resp, err := http.Get(base + "/api/exceptions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list struct {
		Exceptions []exceptionPayload `json:"exceptions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	return list.Exceptions
}

func renewBatch(t *testing.T, base, id string, minutes, revision int) *http.Response {
	t.Helper()
	return postJSON(t, http.MethodPost, base+"/api/exception-batches/renew", map[string]any{
		"id": id, "minutes": minutes, "publishedRevision": revision,
	})
}

// TestHTTPExceptionBatchLifecycle drives one batch through real HTTP:
// atomic create, coherent views (batch list = exception list = decision
// matrix), renewal while live, and lazy expiry that terminates the whole
// batch at once — after which renewal can never resurrect it.
func TestHTTPExceptionBatchLifecycle(t *testing.T) {
	mux := http.NewServeMux()
	srv, c := clockSrv(t, time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC))
	srv.Routes(mux)
	ts := newHTTPTS(t, mux)

	// viewer/billing/read is a same-priority tie -> deny; base/doc/write
	// only matches the wildcard deny. Both are denied on published p1.
	tuples := []map[string]string{
		{"role": "viewer", "resource": "billing", "action": "read"},
		{"role": "base", "resource": "doc", "action": "write"},
	}
	resp := createBatch(t, ts.URL, map[string]any{
		"tuples": tuples, "reason": "演练：统一放行两个被拒组合 5 分钟",
		"ttlMinutes": 5, "publishedRevision": 1,
	})
	if resp.StatusCode != http.StatusCreated {
		buf := make([]byte, 2048)
		n, _ := resp.Body.Read(buf)
		t.Fatalf("create batch status = %d: %s", resp.StatusCode, buf[:n])
	}
	var batch batchPayload
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if batch.ID == "" || batch.PublishedRevision != 1 || len(batch.Members) != 2 {
		t.Fatalf("batch = %+v, want id, pin 1, 2 members", batch)
	}
	wantExpiry := c.t.Add(5 * time.Minute)
	for _, m := range batch.Members {
		if !m.ExpiresAt.Equal(wantExpiry) || m.PublishedRevision != 1 {
			t.Fatalf("member = %+v, want shared expiry pinned to p1", m)
		}
	}

	// The batch list and the exception list describe the same scope.
	listed := mustListBatches(t, ts.URL)
	if len(listed) != 1 || listed[0].ID != batch.ID || len(listed[0].Members) != 2 {
		t.Fatalf("listed batches = %+v", listed)
	}
	exceptions := mustListExceptions(t, ts.URL)
	if len(exceptions) != 2 {
		t.Fatalf("live exceptions = %+v, want the 2 batch members", exceptions)
	}

	// The published matrix releases exactly those two tuples, with the
	// original deny evidence attached; the draft matrix stays rule-only.
	pub := mustDecisions(t, ts.URL, "published")
	for _, tup := range tuples {
		i, _ := findDecision(pub, tup["role"], tup["resource"], tup["action"])
		row := pub.Rows[i]
		if row.Evidence.Decision != "allow" ||
			row.Evidence.Reason != policy.ReasonEmergencyAllow ||
			row.Evidence.ExceptionID == "" || row.Exception == nil {
			t.Fatalf("published row for %v = %+v, want emergency allow", tup, row)
		}
		if row.Evidence.OriginalReason == "" || len(row.Evidence.Winners) == 0 {
			t.Fatalf("published row for %v lost original deny evidence: %+v", tup, row.Evidence)
		}
	}
	draft := mustDecisions(t, ts.URL, "draft")
	i, _ := findDecision(draft, "viewer", "billing", "read")
	if draft.Rows[i].Evidence.Decision != "deny" || draft.Rows[i].Exception != nil {
		t.Fatalf("draft row = %+v, batch must not touch draft decisions", draft.Rows[i])
	}

	// Renewal while every member is live extends all of them to
	// now+minutes, pinned to the same revision.
	c.add(4 * time.Minute)
	r := renewBatch(t, ts.URL, batch.ID, 10, 1)
	if r.StatusCode != http.StatusOK {
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		t.Fatalf("renew status = %d: %s", r.StatusCode, buf[:n])
	}
	var renewed batchPayload
	json.NewDecoder(r.Body).Decode(&renewed)
	r.Body.Close()
	for _, m := range renewed.Members {
		if !m.ExpiresAt.Equal(c.t.Add(10*time.Minute)) || m.PublishedRevision != 1 {
			t.Fatalf("renewed member = %+v, want now+10m pinned to p1", m)
		}
	}

	// At the expiry instant the whole batch terminates at once: batch
	// list, exception list and matrix all agree, and renewal can no
	// longer resurrect the members.
	c.add(10 * time.Minute)
	if got := mustListBatches(t, ts.URL); len(got) != 0 {
		t.Fatalf("batches after expiry = %+v, want none", got)
	}
	if got := mustListExceptions(t, ts.URL); len(got) != 0 {
		t.Fatalf("exceptions after expiry = %+v, want none", got)
	}
	pub = mustDecisions(t, ts.URL, "published")
	i, _ = findDecision(pub, "viewer", "billing", "read")
	if pub.Rows[i].Evidence.Decision != "deny" || pub.Rows[i].Exception != nil {
		t.Fatalf("row after expiry = %+v, want plain deny", pub.Rows[i])
	}

	r = renewBatch(t, ts.URL, batch.ID, 10, 1)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("renew expired status = %d, want 409", r.StatusCode)
	}
	var er errResp
	json.NewDecoder(r.Body).Decode(&er)
	r.Body.Close()
	if er.Code != "batch_expired" {
		t.Fatalf("renew expired code = %s, want batch_expired", er.Code)
	}
	if got := mustListExceptions(t, ts.URL); len(got) != 0 {
		t.Fatalf("expired batch resurrected members: %+v", got)
	}
	if got := mustListBatches(t, ts.URL); len(got) != 0 {
		t.Fatalf("terminated batch re-listed: %+v", got)
	}
}

// TestHTTPExceptionBatchAllOrNothing: when any member of the batch is
// invalid, the whole request is rejected and NOTHING is released — no
// partial exceptions, no half-recorded batch, and the decision matrix
// keeps showing the original deny.
func TestHTTPExceptionBatchAllOrNothing(t *testing.T) {
	mux := http.NewServeMux()
	srv, _ := clockSrv(t, time.Now())
	srv.Routes(mux)
	ts := newHTTPTS(t, mux)

	denied := map[string]string{"role": "base", "resource": "doc", "action": "read"}
	allowed := map[string]string{"role": "admin", "resource": "doc", "action": "delete"}

	assertNoPartialState := func(stage string) {
		t.Helper()
		if got := mustListExceptions(t, ts.URL); len(got) != 0 {
			t.Fatalf("%s: exceptions = %+v, want none", stage, got)
		}
		if got := mustListBatches(t, ts.URL); len(got) != 0 {
			t.Fatalf("%s: batches = %+v, want none", stage, got)
		}
		pub := mustDecisions(t, ts.URL, "published")
		i, _ := findDecision(pub, "base", "doc", "read")
		if pub.Rows[i].Evidence.Decision != "deny" || pub.Rows[i].Exception != nil {
			t.Fatalf("%s: earlier tuple was released anyway: %+v", stage, pub.Rows[i])
		}
	}

	// The LAST tuple is currently allowed -> the whole batch fails and
	// the first tuple must NOT stay released.
	resp := createBatch(t, ts.URL, map[string]any{
		"tuples": []map[string]string{denied, allowed},
		"reason": "x", "ttlMinutes": 5, "publishedRevision": 1,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	var er errResp
	json.NewDecoder(resp.Body).Decode(&er)
	resp.Body.Close()
	if er.Code != "tuple_not_denied" {
		t.Fatalf("code = %s, want tuple_not_denied", er.Code)
	}
	assertNoPartialState("allowed tail")

	// Duplicate tuple inside the batch.
	resp = createBatch(t, ts.URL, map[string]any{
		"tuples": []map[string]string{denied, denied},
		"reason": "x", "ttlMinutes": 5, "publishedRevision": 1,
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate status = %d, want 422", resp.StatusCode)
	}
	resp.Body.Close()
	assertNoPartialState("duplicate")

	// Out-of-domain tuple at the tail.
	resp = createBatch(t, ts.URL, map[string]any{
		"tuples": []map[string]string{denied, {"role": "ghost", "resource": "doc", "action": "read"}},
		"reason": "x", "ttlMinutes": 5, "publishedRevision": 1,
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("foreign status = %d, want 422", resp.StatusCode)
	}
	resp.Body.Close()
	assertNoPartialState("foreign tail")

	// Stale published revision: the batch cannot attach to a revision
	// the admin never adjudicated.
	resp = createBatch(t, ts.URL, map[string]any{
		"tuples": []map[string]string{denied},
		"reason": "x", "ttlMinutes": 5, "publishedRevision": 42,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale revision status = %d, want 409", resp.StatusCode)
	}
	json.NewDecoder(resp.Body).Decode(&er)
	resp.Body.Close()
	if er.Code != "published_moved" {
		t.Fatalf("stale revision code = %s, want published_moved", er.Code)
	}
	assertNoPartialState("stale revision")
}

// TestHTTPExceptionBatchPublishInvalidates: a publish terminates the
// whole batch in the same critical section; afterwards renewal is
// rejected whether it carries the old or the new revision — the batch
// can never attach to a revision it was not adjudicated against.
func TestHTTPExceptionBatchPublishInvalidates(t *testing.T) {
	mux := http.NewServeMux()
	srv, _ := clockSrv(t, time.Now())
	srv.Routes(mux)
	ts := newHTTPTS(t, mux)

	resp := createBatch(t, ts.URL, map[string]any{
		"tuples": []map[string]string{
			{"role": "base", "resource": "doc", "action": "read"},
			{"role": "viewer", "resource": "billing", "action": "read"},
		},
		"reason": "drill", "ttlMinutes": 30, "publishedRevision": 1,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var batch batchPayload
	json.NewDecoder(resp.Body).Decode(&batch)
	resp.Body.Close()

	// Publish a new revision (an unrelated allow rule).
	var st stateResp
	stateResp, err := http.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(stateResp.Body).Decode(&st)
	stateResp.Body.Close()
	doc := st.Draft.Document
	doc.Rules = append(doc.Rules, policy.Rule{
		ID: "audit-read", Role: "viewer", Resource: "auditlog", Action: "read",
		Priority: 50, Effect: policy.EffectAllow,
	})
	save := postJSON(t, http.MethodPut, ts.URL+"/api/draft", doc)
	save.Body.Close()
	prevResp := postJSON(t, http.MethodPost, ts.URL+"/api/preview", nil)
	var preview struct {
		Summary           policy.Summary `json:"summary"`
		DraftRevision     int            `json:"draftRevision"`
		PublishedRevision int            `json:"publishedRevision"`
	}
	json.NewDecoder(prevResp.Body).Decode(&preview)
	prevResp.Body.Close()
	pubResp := postJSON(t, http.MethodPost, ts.URL+"/api/publish", map[string]any{
		"draftRevision":     preview.DraftRevision,
		"publishedRevision": preview.PublishedRevision,
		"summary":           preview.Summary,
	})
	if pubResp.StatusCode != http.StatusOK {
		t.Fatalf("publish status = %d", pubResp.StatusCode)
	}
	pubResp.Body.Close()

	// Every view drops the batch members at once.
	if got := mustListBatches(t, ts.URL); len(got) != 0 {
		t.Fatalf("batches after publish = %+v, want none", got)
	}
	if got := mustListExceptions(t, ts.URL); len(got) != 0 {
		t.Fatalf("exceptions after publish = %+v, want none", got)
	}
	pub := mustDecisions(t, ts.URL, "published")
	for _, row := range pub.Rows {
		if row.Exception != nil || row.Evidence.ExceptionID != "" {
			t.Fatalf("stale exception observable after publish: %+v", row)
		}
	}

	// Renewal with the OLD revision: late request.
	r := renewBatch(t, ts.URL, batch.ID, 5, 1)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("renew old revision status = %d, want 409", r.StatusCode)
	}
	var er errResp
	json.NewDecoder(r.Body).Decode(&er)
	r.Body.Close()
	if er.Code != "published_moved" {
		t.Fatalf("renew old revision code = %s, want published_moved", er.Code)
	}

	// Renewal with the NEW revision: the terminated batch must not
	// attach to a revision it was never adjudicated against.
	r = renewBatch(t, ts.URL, batch.ID, 5, 2)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("renew onto new revision status = %d, want 409", r.StatusCode)
	}
	json.NewDecoder(r.Body).Decode(&er)
	r.Body.Close()
	if er.Code != "published_moved" {
		t.Fatalf("renew onto new revision code = %s, want published_moved", er.Code)
	}

	// Neither attempt resurrected anything.
	if got := mustListExceptions(t, ts.URL); len(got) != 0 {
		t.Fatalf("publish-invalidated batch resurrected: %+v", got)
	}
	if got := mustListBatches(t, ts.URL); len(got) != 0 {
		t.Fatalf("terminated batch re-listed: %+v", got)
	}

	// Unknown batch id -> 404.
	r = renewBatch(t, ts.URL, "batch-999", 5, 2)
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("renew unknown status = %d, want 404", r.StatusCode)
	}
	json.NewDecoder(r.Body).Decode(&er)
	r.Body.Close()
	if er.Code != "batch_not_found" {
		t.Fatalf("renew unknown code = %s, want batch_not_found", er.Code)
	}

	// The tuples stay denied on p2, so a FRESH batch can be adjudicated
	// against the current revision — with brand-new ids.
	resp = createBatch(t, ts.URL, map[string]any{
		"tuples": []map[string]string{
			{"role": "base", "resource": "doc", "action": "read"},
		},
		"reason": "re-adjudicated", "ttlMinutes": 5, "publishedRevision": 2,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("fresh batch on p2 status = %d", resp.StatusCode)
	}
	var fresh batchPayload
	json.NewDecoder(resp.Body).Decode(&fresh)
	resp.Body.Close()
	if fresh.ID == batch.ID || fresh.PublishedRevision != 2 {
		t.Fatalf("fresh batch = %+v, want new id pinned to p2", fresh)
	}
}
