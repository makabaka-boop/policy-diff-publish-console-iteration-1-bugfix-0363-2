package api

import (
	"accesssim/store"
	"net/http"
)

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
func (s *Server) handleExceptionBatches(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.getStore().ExceptionBatches())
}
