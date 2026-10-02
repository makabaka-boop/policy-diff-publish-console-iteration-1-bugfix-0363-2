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
	Active            bool               `json:"active"`
	Members           []exceptionPayload `json:"members"`
}

type batchListPayload struct {
	Batches           []batchPayload `json:"batches"`
	PublishedRevision int            `json:"publishedRevision"`
	Now               string         `json:"now"`
}

func mustListBatches(t *testing.T, base string) batchListPayload {
	t.Helper()
	resp, err := http.Get(base + "/api/exception-batches")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET exception-batches status %d", resp.StatusCode)
	}
	var bl batchListPayload
	if err := json.NewDecoder(resp.Body).Decode(&bl); err != nil {
		t.Fatal(err)
	}
	return bl
}

func postBatch(t *testing.T, base string, body any) *http.Response {
	t.Helper()
	return postJSON(t, http.MethodPost, base+"/api/exception-batches", body)
}

func renewBatch(t *testing.T, base string, body any) *http.Response {
	t.Helper()
	return postJSON(t, http.MethodPost, base+"/api/exception-batches/renew", body)
}

// publishRuleChange adds one allow rule to the draft and publishes it,
// moving the published revision from 1 to 2.
func publishRuleChange(t *testing.T, base string) {
	t.Helper()
	resp, err := http.Get(base + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st stateResp
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	doc := st.Draft.Document
	doc.Rules = append(doc.Rules, policy.Rule{
		ID: "batch-test-x", Role: "viewer", Resource: "auditlog", Action: "write",
		Priority: 40, Effect: policy.EffectAllow,
	})
	sr := postJSON(t, http.MethodPut, base+"/api/draft", doc)
	sr.Body.Close()
	pr := postJSON(t, http.MethodPost, base+"/api/preview", nil)
	var prev struct {
		Summary           policy.Summary `json:"summary"`
		DraftRevision     int            `json:"draftRevision"`
		PublishedRevision int            `json:"publishedRevision"`
	}
	json.NewDecoder(pr.Body).Decode(&prev)
	pr.Body.Close()
	ok := postJSON(t, http.MethodPost, base+"/api/publish", map[string]any{
		"draftRevision":     prev.DraftRevision,
		"publishedRevision": prev.PublishedRevision,
		"summary":           prev.Summary,
	})
	if ok.StatusCode != 200 {
		t.Fatalf("publish status %d", ok.StatusCode)
	}
	ok.Body.Close()
}

// drillTuples are denied on the demo published revision 1:
// viewer/billing/read is a tie-deny, base/doc/read hits only the
// wildcard deny.
var drillTuples = []map[string]string{
	{"role": "viewer", "resource": "billing", "action": "read"},
	{"role": "base", "resource": "doc", "action": "read"},
}

// TestHTTPExceptionBatchLifecycle drives a full drill over HTTP: atomic
// create, coherent views, uniform renewal, then expiry — after which the
// batch is terminated and renewal refuses to revive it.
func TestHTTPExceptionBatchLifecycle(t *testing.T) {
	mux := http.NewServeMux()
	srv, c := clockSrv(t, time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC))
	srv.Routes(mux)
	ts := newHTTPTS(t, mux)
	defer ts.Close()

	resp := postBatch(t, ts.URL, map[string]any{
		"tuples":            drillTuples,
		"publishedRevision": 1,
		"ttlMinutes":        5,
		"reason":            "演练：批量临时放行",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var batch batchPayload
	json.NewDecoder(resp.Body).Decode(&batch)
	resp.Body.Close()
	if batch.ID == "" || !batch.Active || batch.PublishedRevision != 1 || len(batch.Members) != 2 {
		t.Fatalf("batch = %+v", batch)
	}
	if !batch.Members[0].ExpiresAt.Equal(c.t.Add(5*time.Minute)) ||
		batch.Members[0].ExpiresAt != batch.Members[1].ExpiresAt {
		t.Fatalf("members do not share one expiry: %+v", batch.Members)
	}

	// Batch list agrees, with the same adjudication frame.
	bl := mustListBatches(t, ts.URL)
	if bl.PublishedRevision != 1 || len(bl.Batches) != 1 ||
		bl.Batches[0].ID != batch.ID || !bl.Batches[0].Active || bl.Now == "" {
		t.Fatalf("batch list = %+v", bl)
	}

	// Matrix shows both tuples as temporary allows carrying identity.
	d := mustDecisions(t, ts.URL, "published")
	for _, tup := range drillTuples {
		i, _ := findDecision(d, tup["role"], tup["resource"], tup["action"])
		if d.Rows[i].Evidence.Decision != "allow" ||
			d.Rows[i].Evidence.ExceptionID == "" || d.Rows[i].Exception == nil {
			t.Fatalf("row for %v = %+v, want overridden allow", tup, d.Rows[i])
		}
	}

	// Uniform renewal while live.
	c.add(3 * time.Minute)
	rr := renewBatch(t, ts.URL, map[string]any{
		"id": batch.ID, "minutes": 10, "publishedRevision": 1,
	})
	if rr.StatusCode != http.StatusOK {
		t.Fatalf("renew status = %d", rr.StatusCode)
	}
	var renewed batchPayload
	json.NewDecoder(rr.Body).Decode(&renewed)
	rr.Body.Close()
	for _, m := range renewed.Members {
		if !m.ExpiresAt.Equal(c.t.Add(10 * time.Minute)) {
			t.Fatalf("member %s expiry = %v, want uniform renew", m.ID, m.ExpiresAt)
		}
	}

	// Let the renewed batch lapse: renewal must now refuse permanently.
	c.add(10 * time.Minute)
	rr = renewBatch(t, ts.URL, map[string]any{
		"id": batch.ID, "minutes": 10, "publishedRevision": 1,
	})
	if rr.StatusCode != http.StatusConflict {
		t.Fatalf("expired renew status = %d, want 409", rr.StatusCode)
	}
	var er errResp
	json.NewDecoder(rr.Body).Decode(&er)
	rr.Body.Close()
	if er.Code != "batch_expired" {
		t.Fatalf("expired renew code = %s, want batch_expired", er.Code)
	}

	// Nothing was revived: matrix back to plain deny, list empty, batch
	// still queryable but terminated.
	d = mustDecisions(t, ts.URL, "published")
	for _, tup := range drillTuples {
		i, _ := findDecision(d, tup["role"], tup["resource"], tup["action"])
		if d.Rows[i].Evidence.Decision != "deny" || d.Rows[i].Exception != nil {
			t.Fatalf("post-expiry row for %v = %+v", tup, d.Rows[i])
		}
	}
	lr, _ := http.Get(ts.URL + "/api/exceptions")
	var list struct {
		Exceptions []exceptionPayload `json:"exceptions"`
	}
	json.NewDecoder(lr.Body).Decode(&list)
	lr.Body.Close()
	if len(list.Exceptions) != 0 {
		t.Fatalf("revived exceptions listed: %+v", list.Exceptions)
	}
	bl = mustListBatches(t, ts.URL)
	if len(bl.Batches) != 1 || bl.Batches[0].Active {
		t.Fatalf("terminated batch = %+v, want inactive", bl.Batches)
	}
}

// TestHTTPExceptionBatchAtomicReject: one bad member fails the whole
// batch — no partial grants, no phantom batch record.
func TestHTTPExceptionBatchAtomicReject(t *testing.T) {
	mux := http.NewServeMux()
	srv, _ := clockSrv(t, time.Now())
	srv.Routes(mux)
	ts := newHTTPTS(t, mux)
	defer ts.Close()

	cases := []struct {
		name   string
		tuples []map[string]string
		want   int
		code   string
	}{
		{"trailing allowed tuple", []map[string]string{
			drillTuples[0], drillTuples[1],
			{"role": "admin", "resource": "doc", "action": "delete"},
		}, 409, "tuple_not_denied"},
		{"trailing foreign tuple", []map[string]string{
			drillTuples[0], drillTuples[1],
			{"role": "ghost", "resource": "doc", "action": "read"},
		}, 422, "invalid_exception"},
		{"duplicate inside batch", []map[string]string{
			drillTuples[0], drillTuples[0],
		}, 422, "invalid_exception"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postBatch(t, ts.URL, map[string]any{
				"tuples":            tc.tuples,
				"publishedRevision": 1,
				"ttlMinutes":        5,
				"reason":            "drill",
			})
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			var er errResp
			json.NewDecoder(resp.Body).Decode(&er)
			if er.Code != tc.code {
				t.Fatalf("code = %q, want %q", er.Code, tc.code)
			}
			// No partial state in any view.
			lr, _ := http.Get(ts.URL + "/api/exceptions")
			var list struct {
				Exceptions []exceptionPayload `json:"exceptions"`
			}
			json.NewDecoder(lr.Body).Decode(&list)
			lr.Body.Close()
			if len(list.Exceptions) != 0 {
				t.Fatalf("partial exceptions leaked: %+v", list.Exceptions)
			}
			if bl := mustListBatches(t, ts.URL); len(bl.Batches) != 0 {
				t.Fatalf("phantom batch recorded: %+v", bl.Batches)
			}
			d := mustDecisions(t, ts.URL, "published")
			i, _ := findDecision(d, drillTuples[0]["role"], drillTuples[0]["resource"], drillTuples[0]["action"])
			if d.Rows[i].Evidence.Decision != "deny" || d.Rows[i].Exception != nil {
				t.Fatalf("front member was granted despite batch rejection: %+v", d.Rows[i])
			}
		})
	}
}

// TestHTTPExceptionBatchPublishTerminates: after a publish the old batch
// is permanently terminated — renewal fails even when stamped with the
// new revision, and members never attach to it.
func TestHTTPExceptionBatchPublishTerminates(t *testing.T) {
	mux := http.NewServeMux()
	srv, _ := clockSrv(t, time.Now())
	srv.Routes(mux)
	ts := newHTTPTS(t, mux)
	defer ts.Close()

	resp := postBatch(t, ts.URL, map[string]any{
		"tuples":            drillTuples,
		"publishedRevision": 1,
		"ttlMinutes":        30,
		"reason":            "pre-publish drill",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	var batch batchPayload
	json.NewDecoder(resp.Body).Decode(&batch)
	resp.Body.Close()

	publishRuleChange(t, ts.URL)

	// Renewal stamped with the NEW revision must not re-attach the old
	// batch to it.
	rr := renewBatch(t, ts.URL, map[string]any{
		"id": batch.ID, "minutes": 10, "publishedRevision": 2,
	})
	if rr.StatusCode != http.StatusConflict {
		t.Fatalf("renew after publish status = %d, want 409", rr.StatusCode)
	}
	var er errResp
	json.NewDecoder(rr.Body).Decode(&er)
	rr.Body.Close()
	if er.Code != "published_moved" {
		t.Fatalf("renew after publish code = %s, want published_moved", er.Code)
	}

	// Nothing survived or re-attached under p2.
	lr, _ := http.Get(ts.URL + "/api/exceptions")
	var list struct {
		Exceptions []exceptionPayload `json:"exceptions"`
	}
	json.NewDecoder(lr.Body).Decode(&list)
	lr.Body.Close()
	if len(list.Exceptions) != 0 {
		t.Fatalf("members revived after publish: %+v", list.Exceptions)
	}
	d := mustDecisions(t, ts.URL, "published")
	if d.Revision != 2 {
		t.Fatalf("revision = %d, want 2", d.Revision)
	}
	for _, tup := range drillTuples {
		i, _ := findDecision(d, tup["role"], tup["resource"], tup["action"])
		if d.Rows[i].Evidence.ExceptionID != "" || d.Rows[i].Exception != nil {
			t.Fatalf("stale member attached to p2: %+v", d.Rows[i])
		}
	}
	bl := mustListBatches(t, ts.URL)
	if len(bl.Batches) != 1 || bl.Batches[0].Active || bl.Batches[0].PublishedRevision != 1 {
		t.Fatalf("batch after publish = %+v, want terminated and pinned to p1", bl.Batches)
	}
}

// TestHTTPExceptionBatchRenewValidation covers unknown ids and bounds.
func TestHTTPExceptionBatchRenewValidation(t *testing.T) {
	mux := http.NewServeMux()
	srv, _ := clockSrv(t, time.Now())
	srv.Routes(mux)
	ts := newHTTPTS(t, mux)
	defer ts.Close()

	resp := postBatch(t, ts.URL, map[string]any{
		"tuples":            drillTuples,
		"publishedRevision": 1,
		"ttlMinutes":        30,
		"reason":            "drill",
	})
	var batch batchPayload
	json.NewDecoder(resp.Body).Decode(&batch)
	resp.Body.Close()

	cases := []struct {
		name string
		body map[string]any
		want int
		code string
	}{
		{"unknown batch", map[string]any{"id": "batch-nope", "minutes": 10, "publishedRevision": 1},
			404, "batch_not_found"},
		{"minutes zero", map[string]any{"id": batch.ID, "minutes": 0, "publishedRevision": 1},
			422, "invalid_exception"},
		{"minutes 61", map[string]any{"id": batch.ID, "minutes": 61, "publishedRevision": 1},
			422, "invalid_exception"},
		{"stale revision", map[string]any{"id": batch.ID, "minutes": 10, "publishedRevision": 42},
			409, "published_moved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := renewBatch(t, ts.URL, tc.body)
			defer r.Body.Close()
			if r.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", r.StatusCode, tc.want)
			}
			var er errResp
			json.NewDecoder(r.Body).Decode(&er)
			if er.Code != tc.code {
				t.Fatalf("code = %q, want %q", er.Code, tc.code)
			}
		})
	}
}
