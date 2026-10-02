package store

import (
	"accesssim/policy"
	"fmt"
	"time"
)

type ExceptionBatch struct {
	ID                string                `json:"id"`
	PublishedRevision int                   `json:"publishedRevision"`
	Members           []*EmergencyException `json:"members"`
	Reason            string                `json:"reason"`
}
type ExceptionBatchRequest struct {
	Tuples            []policy.Tuple `json:"tuples"`
	PublishedRevision int            `json:"publishedRevision"`
	TTLMinutes        int            `json:"ttlMinutes"`
	Reason            string         `json:"reason"`
}

func (s *Store) CreateExceptionBatch(req ExceptionBatchRequest) (*ExceptionBatch, error) {
	if len(req.Tuples) == 0 || len(req.Tuples) > 32 {
		return nil, ErrInvalidException
	}
	batch := &ExceptionBatch{PublishedRevision: req.PublishedRevision, Reason: req.Reason}
	for _, tuple := range req.Tuples {
		result, err := s.CreateEmergencyException(&CreateExceptionRequest{Tuple: tuple,
			PublishedRevision: req.PublishedRevision, TTLMinutes: req.TTLMinutes, Reason: req.Reason})
		if err != nil {
			return nil, err
		}
		batch.Members = append(batch.Members, result.Exception)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.batches == nil {
		s.batches = map[string]*ExceptionBatch{}
	}
	batch.ID = fmt.Sprintf("batch-%d", s.exceptionSeq)
	s.batches[batch.ID] = batch
	return batch, nil
}

func (s *Store) RenewExceptionBatch(id string, minutes, revision int) (*ExceptionBatch, error) {
	if minutes < 1 || minutes > 60 {
		return nil, ErrInvalidException
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.published.Revision {
		return nil, ErrExceptionRevisionMoved
	}
	batch := s.batches[id]
	if batch == nil {
		return nil, ErrInvalidException
	}
	now := s.now()
	live := s.pruneExceptionsLocked(now)
	for _, ex := range batch.Members {
		ex.ExpiresAt = now.Add(time.Duration(minutes) * time.Minute)
		ex.PublishedRevision = revision
		present := false
		for _, active := range live {
			if active.ID == ex.ID {
				present = true
			}
		}
		if !present {
			s.exceptions = append(s.exceptions, ex)
		}
	}
	batch.PublishedRevision = revision
	return batch, nil
}

func (s *Store) ExceptionBatches() []ExceptionBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ExceptionBatch{}
	for _, batch := range s.batches {
		out = append(out, *batch)
	}
	return out
}
