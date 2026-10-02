package api

import (
	"accesssim/store"
	"net/http"
	"time"
)

// handleExceptionBatch creates a whole drill batch atomically: either
// every tuple gets its temporary allow (and the batch is registered and
// visible everywhere), or the request fails and no partial state exists.
func (s *Server) handleExceptionBatch(w http.ResponseWriter, r *http.Request) {
	var req store.ExceptionBatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	result, err := s.getStore().CreateExceptionBatch(req)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, result)
}

// handleRenewExceptionBatch uniformly extends a still-effective batch.
// A batch whose members expired, or whose pinned revision was superseded
// by a publish/reset, is terminated permanently: renewal then fails
// instead of reviving it.
func (s *Server) handleRenewExceptionBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                string `json:"id"`
		Minutes           int    `json:"minutes"`
		PublishedRevision int    `json:"publishedRevision"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	result, err := s.getStore().RenewExceptionBatch(req.ID, req.Minutes, req.PublishedRevision)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

// handleExceptionBatches lists every recorded batch with its derived
// active marker, plus the published revision and adjudication clock of
// the same critical section — the same frame of reference the single
// exception list and the decision matrix use.
func (s *Server) handleExceptionBatches(w http.ResponseWriter, r *http.Request) {
	pubRev, now, batches := s.getStore().ExceptionBatches()
	writeJSON(w, 200, map[string]any{
		"batches":           batches,
		"publishedRevision": pubRev,
		"now":               now.Format(time.RFC3339),
	})
}
