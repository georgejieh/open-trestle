// Package inventory serves stored items over HTTP.
package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ErrNotFound reports that no item has the requested identifier.
var ErrNotFound = errors.New("item not found")

// Item is one stored inventory item.
type Item struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Quantity int    `json:"quantity"`
}

// Store holds items by identifier.
type Store struct {
	items map[string]Item
}

// NewStore returns a Store holding items.
func NewStore(items map[string]Item) *Store {
	return &Store{items: items}
}

// Get returns the item with identifier id.
func (s *Store) Get(id string) (Item, error) {
	item, ok := s.items[id]
	if !ok {
		return Item{}, fmt.Errorf("get item %q: %v", id, ErrNotFound)
	}
	return item, nil
}

// Handler serves GET /items/{id}.
type Handler struct {
	Store *Store
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	item, err := h.Store.Get(id)
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(item)
}
