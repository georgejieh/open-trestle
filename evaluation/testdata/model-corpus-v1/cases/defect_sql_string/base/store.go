// Package documents reads document metadata from SQL.
package documents

import (
	"context"
	"database/sql"
)

// Store reads document metadata.
type Store struct {
	db *sql.DB
}

// NewStore returns a Store backed by db.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Title returns the title of document id.
func (s *Store) Title(ctx context.Context, id int64) (string, error) {
	var title string
	err := s.db.QueryRowContext(ctx, "SELECT title FROM documents WHERE id = ?", id).Scan(&title)
	return title, err
}
