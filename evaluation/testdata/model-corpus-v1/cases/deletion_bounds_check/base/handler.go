package results

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// EntryHandler serves GET /results/{position} from one page.
type EntryHandler struct {
	Page *Page
}

func (h EntryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	position, err := strconv.Atoi(r.PathValue("position"))
	if err != nil {
		http.Error(w, "position must be an integer", http.StatusBadRequest)
		return
	}
	entry, err := h.Page.At(position)
	if errors.Is(err, ErrOutOfRange) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entry)
}
