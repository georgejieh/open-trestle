// Package exports serves generated export files.
package exports

import (
	"net/http"
	"os"
	"sort"
)

// Server serves the files in one export directory.
type Server struct {
	exportDir string
}

// NewServer returns a Server for the files in exportDir.
func NewServer(exportDir string) *Server {
	return &Server{exportDir: exportDir}
}

// Routes registers the export endpoints on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /exports", s.handleList)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.exportDir)
	if err != nil {
		http.Error(w, "exports unavailable", http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := w.Write([]byte(name + "\n")); err != nil {
			return
		}
	}
}
