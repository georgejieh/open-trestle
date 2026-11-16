package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// The release channel reads GitHub Releases with unauthenticated HTTPS GETs:
// the release list from the API, then a chosen release's signature, sidecar
// and archive. No credential, cookie or identifier is sent; the only request
// header beyond the defaults is a fixed User-Agent and Accept. A response is
// bounded, must be HTTP 200, and may redirect only to the GitHub hosts that
// serve it over HTTPS. What GitHub returns is untrusted: an archive is used
// only after its signature verifies with a pinned key.

const (
	// Repository is the GitHub repository whose releases are read.
	Repository = "georgejieh/open-trestle"
	// ReleasesURL is the one request an update check makes.
	ReleasesURL = "https://api.github.com/repos/" + Repository + "/releases?per_page=20"
	// MaxReleasesBytes bounds the release list.
	MaxReleasesBytes = 4 << 20
	// MaxSidecarBytes bounds a SHA-256 sidecar.
	MaxSidecarBytes = 1024

	downloadPrefix    = "https://github.com/" + Repository + "/releases/download/"
	maxListedReleases = 100
	maxRedirects      = 5
	userAgent         = "open-trestle-update"
)

var (
	// ErrReleasesUnavailable is a release list or asset that could not be
	// read: no answer, a status other than 200, a refused redirect or a body
	// over its bound.
	ErrReleasesUnavailable = errors.New("GitHub Releases could not be read")
	// ErrReleasesMalformed is a release list that is not the expected JSON.
	ErrReleasesMalformed = errors.New("GitHub Releases answered with an unexpected document")

	apiHosts      = map[string]bool{"api.github.com": true}
	downloadHosts = map[string]bool{"github.com": true, "objects.githubusercontent.com": true, "release-assets.githubusercontent.com": true}
)

// Asset is one downloadable file of a release.
type Asset struct {
	URL  string
	Size int64
}

// Release is a published release with the three assets an update needs.
type Release struct {
	Tag        string
	Version    Version
	Prerelease bool
	Archive    Asset
	Sidecar    Asset
	Signature  Asset
}

type githubAsset struct {
	Name  *string `json:"name"`
	Size  *int64  `json:"size"`
	URL   *string `json:"browser_download_url"`
	State *string `json:"state"`
}

type githubRelease struct {
	TagName    *string        `json:"tag_name"`
	Draft      *bool          `json:"draft"`
	Prerelease *bool          `json:"prerelease"`
	Assets     *[]githubAsset `json:"assets"`
}

// ParseReleases reads a GitHub release list. A document that is not a JSON
// array of release objects with the expected field types is refused. A
// release that cannot qualify is left out, not refused: a draft, a tag that
// is not "v" and a SemVer version, a missing, repeated, not-yet-uploaded or
// oversized archive, sidecar or signature asset, or an asset URL other than
// this repository's release download address for that tag.
func ParseReleases(body []byte) ([]Release, error) {
	var listed []githubRelease
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&listed); err != nil || listed == nil {
		return nil, fmt.Errorf("%w: not a JSON array of releases", ErrReleasesMalformed)
	}
	if !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return nil, fmt.Errorf("%w: data after the release list", ErrReleasesMalformed)
	}
	if len(listed) > maxListedReleases {
		return nil, fmt.Errorf("%w: more than %d releases", ErrReleasesMalformed, maxListedReleases)
	}
	releases := []Release{}
	for _, item := range listed {
		if item.TagName == nil || item.Draft == nil || item.Prerelease == nil || item.Assets == nil {
			return nil, fmt.Errorf("%w: a release lacks tag_name, draft, prerelease or assets", ErrReleasesMalformed)
		}
		assets := map[string][]Asset{}
		for _, asset := range *item.Assets {
			if asset.Name == nil || asset.Size == nil || asset.URL == nil {
				return nil, fmt.Errorf("%w: an asset lacks name, size or browser_download_url", ErrReleasesMalformed)
			}
			if asset.State != nil && *asset.State != "uploaded" {
				continue
			}
			assets[*asset.Name] = append(assets[*asset.Name], Asset{URL: *asset.URL, Size: *asset.Size})
		}
		if release, ok := qualifies(*item.TagName, *item.Draft, *item.Prerelease, assets); ok {
			releases = append(releases, release)
		}
	}
	return releases, nil
}

func qualifies(tag string, draft, prerelease bool, assets map[string][]Asset) (Release, bool) {
	if draft || len(tag) < 2 || tag[0] != 'v' {
		return Release{}, false
	}
	version, err := ParseVersion(tag[1:])
	if err != nil {
		return Release{}, false
	}
	release := Release{Tag: tag, Version: version, Prerelease: prerelease}
	for _, want := range []struct {
		name   string
		limit  int64
		target *Asset
	}{
		{ArchiveName, MaxArchiveBytes, &release.Archive},
		{SidecarName, MaxSidecarBytes, &release.Sidecar},
		{SignatureName, MaxSignatureBytes, &release.Signature},
	} {
		found := assets[want.name]
		if len(found) != 1 || found[0].Size <= 0 || found[0].Size > want.limit || found[0].URL != downloadPrefix+tag+"/"+want.name {
			return Release{}, false
		}
		*want.target = found[0]
	}
	return release, true
}

// Latest is the release with the highest version, leaving out prereleases
// (by GitHub's flag or a SemVer prerelease part) unless includePrereleases.
func Latest(releases []Release, includePrereleases bool) (Release, bool) {
	var best Release
	found := false
	for _, release := range releases {
		if !includePrereleases && (release.Prerelease || release.Version.Prerelease()) {
			continue
		}
		if !found || release.Version.Compare(best.Version) > 0 {
			best, found = release, true
		}
	}
	return best, found
}

// Newest is the release an install of installed may move to: strictly newer,
// and a prerelease only when installed is one too.
func Newest(releases []Release, installed Version) (Release, bool) {
	release, found := Latest(releases, installed.Prerelease())
	if !found || release.Version.Compare(installed) <= 0 {
		return Release{}, false
	}
	return release, true
}

// Client reads GitHub Releases over HTTPS.
type Client struct {
	// Transport replaces the default HTTPS transport; tests set it.
	Transport http.RoundTripper
}

func (c Client) transport() http.RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true,
	}
}

// refusedRedirect is a redirect the release reader does not follow.
type refusedRedirect string

func (r refusedRedirect) Error() string { return string(r) }

// get performs one GET of address, following at most maxRedirects redirects
// to allowed HTTPS hosts, and returns the HTTP 200 response.
func (c Client) get(ctx context.Context, address, accept string, allowed map[string]bool) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil || request.URL.Scheme != "https" || !allowed[request.URL.Hostname()] || request.URL.Port() != "" {
		return nil, fmt.Errorf("%w: %s is not an address this update reads", ErrReleasesUnavailable, address)
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", accept)
	client := &http.Client{Transport: c.transport(), CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return refusedRedirect("too many redirects")
		}
		if next.URL.Scheme != "https" || !allowed[next.URL.Hostname()] || next.URL.Port() != "" || next.URL.User != nil {
			return refusedRedirect("a redirect to " + next.URL.Scheme + "://" + next.URL.Host + " was refused")
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		var refused refusedRedirect
		switch {
		case errors.As(err, &refused):
			return nil, fmt.Errorf("%w: %s", ErrReleasesUnavailable, string(refused))
		case ctx.Err() != nil:
			return nil, fmt.Errorf("%w: no answer in time", ErrReleasesUnavailable)
		}
		return nil, fmt.Errorf("%w: GitHub could not be reached", ErrReleasesUnavailable)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		hint := ""
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
			hint = " (GitHub allows 60 unauthenticated requests an hour from one address; try again later)"
		}
		return nil, fmt.Errorf("%w: GitHub answered HTTP %d%s", ErrReleasesUnavailable, response.StatusCode, hint)
	}
	return response, nil
}

// Releases reads the release list within timeout.
func (c Client) Releases(ctx context.Context, timeout time.Duration) ([]Release, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body bytes.Buffer
	if _, err := c.copy(ctx, ReleasesURL, "application/vnd.github+json", apiHosts, MaxReleasesBytes, &body); err != nil {
		return nil, err
	}
	return ParseReleases(body.Bytes())
}

// Download copies one release asset of at most limit bytes to destination
// within timeout and returns its size. Only this repository's release
// download addresses are read.
func (c Client) Download(ctx context.Context, asset Asset, limit int64, timeout time.Duration, destination io.Writer) (int64, error) {
	if !strings.HasPrefix(asset.URL, downloadPrefix) || len(asset.URL) == len(downloadPrefix) {
		return 0, fmt.Errorf("%w: %s is not a release download of %s", ErrReleasesUnavailable, asset.URL, Repository)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.copy(ctx, asset.URL, "application/octet-stream", downloadHosts, limit, destination)
}

func (c Client) copy(ctx context.Context, address, accept string, allowed map[string]bool, limit int64, destination io.Writer) (int64, error) {
	response, err := c.get(ctx, address, accept, allowed)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.ContentLength > limit {
		return 0, fmt.Errorf("%w: the response is larger than %d bytes", ErrReleasesUnavailable, limit)
	}
	written, err := io.Copy(destination, io.LimitReader(response.Body, limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return written, fmt.Errorf("%w: the download did not finish in time", ErrReleasesUnavailable)
		}
		return written, fmt.Errorf("%w: the download was interrupted", ErrReleasesUnavailable)
	}
	if written > limit {
		return written, fmt.Errorf("%w: the response is larger than %d bytes", ErrReleasesUnavailable, limit)
	}
	return written, nil
}
