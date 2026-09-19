package webconsole

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHandlerServesConsoleWithBrowserSecurityBoundary(t *testing.T) {
	handler := NewHandler()
	request := httptest.NewRequest(http.MethodGet, "https://trestle.test/console/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	result := response.Result()
	body, _ := io.ReadAll(result.Body)
	if result.StatusCode != http.StatusOK || !strings.Contains(string(body), `id="root"`) || result.Header.Get("Content-Security-Policy") == "" || result.Header.Get("Cache-Control") != "no-store" || result.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("response=(%d,%q,%q)", result.StatusCode, result.Header, string(body))
	}
}
func TestHandlerRestrictsMethodsQueriesAndUnknownAssets(t *testing.T) {
	handler := NewHandler()
	for _, tc := range []struct {
		method, path string
		status       int
	}{{http.MethodPost, "/console/", http.StatusMethodNotAllowed}, {http.MethodGet, "/console/?token=secret", http.StatusBadRequest}, {http.MethodGet, "/console/assets/missing.js", http.StatusNotFound}, {http.MethodGet, "/console/assets/../index.html", http.StatusBadRequest}, {http.MethodGet, "/other", http.StatusNotFound}} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(tc.method, "https://trestle.test"+tc.path, nil))
		if response.Code != tc.status {
			t.Errorf("%s %s=%d", tc.method, tc.path, response.Code)
		}
		if tc.status == http.StatusNotFound && response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s cache=%q", tc.path, response.Header().Get("Cache-Control"))
		}
	}
}
func TestHandlerRedirectsCanonicalConsolePath(t *testing.T) {
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://trestle.test/console", nil))
	if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != "/console/" {
		t.Fatalf("response=(%d,%q)", response.Code, response.Header().Get("Location"))
	}
}

func TestHandlerServesHashedAssetsAsImmutable(t *testing.T) {
	matches, err := fs.Glob(consoleFiles, "dist/assets/*.js")
	if err != nil || len(matches) != 2 {
		t.Fatalf("assets=(%v,%v)", matches, err)
	}
	for _, match := range matches {
		response := httptest.NewRecorder()
		NewHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://trestle.test/console/assets/"+filepath.Base(match), nil))
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || !strings.Contains(response.Header().Get("Content-Type"), "javascript") {
			t.Fatalf("response=(%d,%q,%q)", response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestHandlerRejectsNonDistributionArtifactsEvenWhenPresent(t *testing.T) {
	filesystem := fstest.MapFS{
		"assets/notes.txt":              {Data: []byte("private fixture")},
		"assets/notes.json":             {Data: []byte("{}")},
		"assets/index-Abc123.js.map":    {Data: []byte("{}")},
		"assets/notes-Abc123.js":        {Data: []byte("private fixture")},
		"assets/index.js":               {Data: []byte("private fixture")},
		"assets/SetupApp.css":           {Data: []byte("private fixture")},
		"assets/nested/index-Abc123.js": {Data: []byte("private fixture")},
		"assets/index-link.js":          {Data: []byte("target"), Mode: fs.ModeSymlink},
		"assets/index-directory.js":     {Mode: fs.ModeDir},
	}
	handler := &Handler{filesystem: filesystem, assets: http.FileServer(http.FS(filesystem))}
	for name := range filesystem {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(method, "https://trestle.test/console/"+name, nil))
			if response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s %s=(%d,%q)", method, name, response.Code, response.Header())
			}
		}
	}
}

func TestHandlerServesOnlyRegularHashedAssetNames(t *testing.T) {
	filesystem := fstest.MapFS{
		"assets/index-Abc_123-.js":    {Data: []byte("export {};")},
		"assets/SetupApp-Abc_123-.js": {Data: []byte("export {};")},
		"assets/index-Abc_123-.css":   {Data: []byte("body {}")},
		"favicon.svg":                 {Data: []byte("<svg></svg>")},
	}
	handler := &Handler{filesystem: filesystem, assets: http.FileServer(http.FS(filesystem))}
	for name := range filesystem {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(method, "https://trestle.test/console/"+name, nil))
			if response.Code != http.StatusOK {
				t.Errorf("%s %s=%d", method, name, response.Code)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Errorf("HEAD %s returned a body", name)
			}
		}
	}
}

func TestHandlerServesSetupApplicationWithoutQueryState(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		response := httptest.NewRecorder()
		NewHandler().ServeHTTP(response, httptest.NewRequest(method, "https://trestle.test/console/setup", nil))
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s=(%d,%q)", method, response.Code, response.Header())
		}
	}
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://trestle.test/console/setup?token=secret", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("query=%d", response.Code)
	}
}
