// Package docs manages shared documents.
package docs

import (
	"context"
	"errors"
	"log"
)

// ErrForbidden reports that the caller may not perform the operation.
var ErrForbidden = errors.New("docs: forbidden")

// User is an authenticated caller.
type User struct {
	ID    string
	Admin bool
}

// Document is stored document metadata.
type Document struct {
	ID      string
	OwnerID string
}

// Store persists documents.
type Store interface {
	Get(ctx context.Context, id string) (Document, error)
	Delete(ctx context.Context, id string) error
}

// Service applies access rules to document operations.
type Service struct {
	store Store
	log   *log.Logger
}

// NewService returns a Service over store that logs to logger.
func NewService(store Store, logger *log.Logger) *Service {
	return &Service{store: store, log: logger}
}

// Delete removes document id on behalf of caller. Only the document's owner or
// an administrator may delete it.
func (s *Service) Delete(ctx context.Context, caller User, id string) error {
	doc, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.log.Printf("document %s deleted by %s", doc.ID, caller.ID)
	return nil
}
