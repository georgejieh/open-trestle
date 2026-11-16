package testsupport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
)

// FakeGitHub is an http.RoundTripper that answers fixed responses by exact
// URL and records every request, so update tests never touch the network. A
// URL it has no response for fails like an unreachable host.
type FakeGitHub struct {
	mu        sync.Mutex
	responses map[string]FakeResponse
	requests  []FakeRequest
}

// FakeResponse is one canned answer. A Location makes it a 302 redirect.
type FakeResponse struct {
	Status   int
	Body     []byte
	Location string
	// ContentLength, when nonzero, is announced instead of len(Body).
	ContentLength int64
}

// FakeRequest is what one request carried.
type FakeRequest struct {
	Method, URL string
	Header      http.Header
}

// NewFakeGitHub returns a fake with no responses.
func NewFakeGitHub() *FakeGitHub { return &FakeGitHub{responses: map[string]FakeResponse{}} }

// Set answers url with response from now on.
func (f *FakeGitHub) Set(url string, response FakeResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[url] = response
}

// Requests returns the requests made so far.
func (f *FakeGitHub) Requests() []FakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeRequest(nil), f.requests...)
}

// RoundTrip implements http.RoundTripper.
func (f *FakeGitHub) RoundTrip(request *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, FakeRequest{Method: request.Method, URL: request.URL.String(), Header: request.Header.Clone()})
	response, found := f.responses[request.URL.String()]
	f.mu.Unlock()
	if !found {
		return nil, errors.New("fake GitHub: no route to host")
	}
	status := response.Status
	if status == 0 {
		status = http.StatusOK
	}
	header := http.Header{}
	if response.Location != "" {
		status = http.StatusFound
		header.Set("Location", response.Location)
	}
	length := int64(len(response.Body))
	if response.ContentLength != 0 {
		length = response.ContentLength
	}
	if length >= 0 {
		header.Set("Content-Length", strconv.FormatInt(length, 10))
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Header: header, ContentLength: length,
		Body: io.NopCloser(bytes.NewReader(response.Body)), Request: request, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}, nil
}

// GitHubReleaseAsset is one asset of a release in GitHub's release JSON.
type GitHubReleaseAsset struct {
	Name string
	Size int64
	URL  string
}

// GitHubReleaseJSON is one release object as GitHub's list endpoint writes
// it, with the fields an update reads and a few it ignores.
func GitHubReleaseJSON(tag string, draft, prerelease bool, assets []GitHubReleaseAsset) map[string]any {
	listed := []any{}
	for _, asset := range assets {
		listed = append(listed, map[string]any{
			"name": asset.Name, "size": asset.Size, "browser_download_url": asset.URL,
			"state": "uploaded", "content_type": "application/octet-stream", "download_count": 3,
		})
	}
	return map[string]any{
		"tag_name": tag, "draft": draft, "prerelease": prerelease, "assets": listed,
		"name": "Open Trestle " + tag, "body": "Release notes for " + tag + ".",
		"html_url": "https://github.com/georgejieh/open-trestle/releases/tag/" + tag,
	}
}

// GitHubReleaseList encodes release objects as the list endpoint's body.
func GitHubReleaseList(releases ...map[string]any) []byte {
	if releases == nil {
		releases = []map[string]any{}
	}
	body, err := json.Marshal(releases)
	if err != nil {
		panic(err)
	}
	return body
}
