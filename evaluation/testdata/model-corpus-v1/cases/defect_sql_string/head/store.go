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

// TitlesByOwner returns the titles of the documents owned by owner, in title
// order.
func (s *Store) TitlesByOwner(ctx context.Context, owner string) ([]string, error) {
	query := "SELECT title FROM documents WHERE owner = '" + owner + "' ORDER BY title"
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var titles []string
	for rows.Next() {
		var title string
		if err := rows.Scan(&title); err != nil {
			return nil, err
		}
		titles = append(titles, title)
	}
	return titles, rows.Err()
}
