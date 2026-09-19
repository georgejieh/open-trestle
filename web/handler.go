// Package webconsole serves the embedded, read-only Open Trestle console.
package webconsole

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
)

//go:embed dist
var consoleFiles embed.FS

var consoleAssetName = regexp.MustCompile(`^/console/assets/(index-[A-Za-z0-9_-]+\.(js|css)|SetupApp-[A-Za-z0-9_-]+\.js)$`)

type Handler struct {
	filesystem fs.FS
	assets     http.Handler
}

func NewHandler() *Handler {
	sub, err := fs.Sub(consoleFiles, "dist")
	if err != nil {
		panic("embedded console is unavailable")
	}
	return &Handler{filesystem: sub, assets: http.FileServer(http.FS(sub))}
}
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setConsoleHeaders(writer.Header())
	if request == nil || request.URL == nil {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cleanPath := path.Clean(request.URL.Path)
	canonicalPath := request.URL.Path == cleanPath || strings.HasSuffix(request.URL.Path, "/") && request.URL.Path == cleanPath+"/"
	if request.URL.RawQuery != "" || !canonicalPath {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	switch {
	case request.URL.Path == "/console":
		http.Redirect(writer, request, "/console/", http.StatusPermanentRedirect)
	case request.URL.Path == "/console/" || request.URL.Path == "/console/setup":
		writer.Header().Set("Cache-Control", "no-store")
		serveEmbeddedIndex(writer, request)
	case consoleAssetName.MatchString(request.URL.Path) || request.URL.Path == "/console/favicon.svg":
		relative := strings.TrimPrefix(request.URL.Path, "/console/")
		information, err := fs.Stat(h.filesystem, relative)
		if err != nil || !information.Mode().IsRegular() {
			http.NotFound(writer, request)
			return
		}
		if request.URL.Path == "/console/favicon.svg" {
			writer.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
		} else {
			writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		clone := request.Clone(request.Context())
		clone.URL.Path = strings.TrimPrefix(request.URL.Path, "/console")
		h.assets.ServeHTTP(writer, clone)
	default:
		http.NotFound(writer, request)
	}
}
func serveEmbeddedIndex(writer http.ResponseWriter, request *http.Request) {
	content, err := consoleFiles.ReadFile("dist/index.html")
	if err != nil {
		http.Error(writer, "console unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
	if request.Method == http.MethodGet {
		_, _ = writer.Write(content)
	}
}
func setConsoleHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}
