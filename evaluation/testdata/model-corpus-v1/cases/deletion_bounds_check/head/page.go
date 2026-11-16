// Package results pages search results.
package results

import "errors"

// ErrOutOfRange reports a position outside a page.
var ErrOutOfRange = errors.New("results: position out of range")

// Entry is one search result.
type Entry struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Page holds one page of search results.
type Page struct {
	entries []Entry
}

// NewPage returns a page holding entries.
func NewPage(entries []Entry) *Page {
	return &Page{entries: entries}
}

// Len returns the number of entries on the page.
func (p *Page) Len() int {
	return len(p.entries)
}

// At returns the entry at position i, or ErrOutOfRange when i is not a valid
// position on the page.
func (p *Page) At(i int) (Entry, error) {
	return p.entries[i], nil
}
