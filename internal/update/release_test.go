package update

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/testsupport"
)

// No test here reaches the network: every request goes to a FakeGitHub.

func releaseAssets(tag string) []testsupport.GitHubReleaseAsset {
	prefix := "https://github.com/georgejieh/open-trestle/releases/download/" + tag + "/"
	return []testsupport.GitHubReleaseAsset{
		{Name: ArchiveName, Size: 70 << 20, URL: prefix + ArchiveName},
		{Name: SidecarName, Size: 95, URL: prefix + SidecarName},
		{Name: SignatureName, Size: 600, URL: prefix + SignatureName},
		{Name: "open-trestle.spdx.json", Size: 12, URL: prefix + "open-trestle.spdx.json"},
	}
}

func without(assets []testsupport.GitHubReleaseAsset, name string) []testsupport.GitHubReleaseAsset {
	kept := []testsupport.GitHubReleaseAsset{}
	for _, asset := range assets {
		if asset.Name != name {
			kept = append(kept, asset)
		}
	}
	return kept
}

func TestParseReleasesKeepsOnlyQualifyingReleases(t *testing.T) {
	wrongHost := releaseAssets("v0.9.0")
	wrongHost[0].URL = "https://example.com/" + ArchiveName
	repeated := append(releaseAssets("v0.8.0"), releaseAssets("v0.8.0")[2])
	oversized := releaseAssets("v0.7.0")
	oversized[0].Size = MaxArchiveBytes + 1
	body := testsupport.GitHubReleaseList(
		testsupport.GitHubReleaseJSON("v0.3.0-rc.1", false, true, releaseAssets("v0.3.0-rc.1")),
		testsupport.GitHubReleaseJSON("v9.0.0", true, false, releaseAssets("v9.0.0")),
		testsupport.GitHubReleaseJSON("v0.2.0", false, false, releaseAssets("v0.2.0")),
		testsupport.GitHubReleaseJSON("nightly", false, false, releaseAssets("nightly")),
		testsupport.GitHubReleaseJSON("v1.0.0", false, false, without(releaseAssets("v1.0.0"), SignatureName)),
		testsupport.GitHubReleaseJSON("v0.9.0", false, false, wrongHost),
		testsupport.GitHubReleaseJSON("v0.8.0", false, false, repeated),
		testsupport.GitHubReleaseJSON("v0.7.0", false, false, oversized),
		testsupport.GitHubReleaseJSON("v0.1.0", false, false, releaseAssets("v0.1.0")),
	)
	releases, err := ParseReleases(body)
	if err != nil {
		t.Fatal(err)
	}
	tags := []string{}
	for _, release := range releases {
		tags = append(tags, release.Tag)
	}
	if strings.Join(tags, " ") != "v0.3.0-rc.1 v0.2.0 v0.1.0" {
		t.Fatalf("qualifying releases %v", tags)
	}
	if releases[1].Archive.URL != "https://github.com/georgejieh/open-trestle/releases/download/v0.2.0/"+ArchiveName || releases[1].Archive.Size != 70<<20 || releases[1].Signature.Size != 600 {
		t.Fatalf("assets %+v", releases[1])
	}
	for installed, want := range map[string]string{
		"0.1.0":       "v0.2.0",
		"0.1.5-dev":   "v0.3.0-rc.1",
		"0.2.0":       "",
		"0.3.0-rc.1":  "",
		"0.3.0-dev":   "v0.3.0-rc.1",
		"0.0.1":       "v0.2.0",
		"0.2.1-alpha": "v0.3.0-rc.1",
	} {
		release, found := Newest(releases, mustVersion(t, installed))
		if (want == "") == found || found && release.Tag != want {
			t.Fatalf("installed %s: newest %s (found %v), want %q", installed, release.Tag, found, want)
		}
	}
}

func TestParseReleasesRefusesMalformedLists(t *testing.T) {
	for name, body := range map[string]string{
		"not an array":       `{"message":"Not Found"}`,
		"null":               `null`,
		"tag not a string":   `[{"tag_name":2,"draft":false,"prerelease":false,"assets":[]}]`,
		"missing assets":     `[{"tag_name":"v1.0.0","draft":false,"prerelease":false}]`,
		"assets not a list":  `[{"tag_name":"v1.0.0","draft":false,"prerelease":false,"assets":{}}]`,
		"asset without size": `[{"tag_name":"v1.0.0","draft":false,"prerelease":false,"assets":[{"name":"a","browser_download_url":"u"}]}]`,
		"trailing data":      `[] []`,
		"truncated":          `[{"tag_name":"v1.0.0"`,
		"too many":           "[" + strings.TrimSuffix(strings.Repeat(`{"tag_name":"x","draft":true,"prerelease":false,"assets":[]},`, 101), ",") + "]",
	} {
		if _, err := ParseReleases([]byte(body)); !errors.Is(err, ErrReleasesMalformed) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
	if releases, err := ParseReleases([]byte(`[]`)); err != nil || len(releases) != 0 {
		t.Fatalf("an empty list: %v %v", releases, err)
	}
}

func TestReleasesReadsTheListWithOneUnauthenticatedGet(t *testing.T) {
	fake := testsupport.NewFakeGitHub()
	fake.Set(ReleasesURL, testsupport.FakeResponse{Body: testsupport.GitHubReleaseList(testsupport.GitHubReleaseJSON("v0.2.0", false, false, releaseAssets("v0.2.0")))})
	releases, err := Client{Transport: fake}.Releases(context.Background(), time.Second)
	if err != nil || len(releases) != 1 || releases[0].Tag != "v0.2.0" {
		t.Fatalf("releases=%v err=%v", releases, err)
	}
	requests := fake.Requests()
	if len(requests) != 1 || requests[0].Method != "GET" || requests[0].URL != "https://api.github.com/repos/georgejieh/open-trestle/releases?per_page=20" {
		t.Fatalf("requests %+v", requests)
	}
	for name := range requests[0].Header {
		if name != "User-Agent" && name != "Accept" {
			t.Fatalf("the release list request carried %s: %v", name, requests[0].Header)
		}
	}
	if requests[0].Header.Get("User-Agent") != "open-trestle-update" {
		t.Fatalf("user agent %q", requests[0].Header.Get("User-Agent"))
	}
}

func TestReleasesRefusals(t *testing.T) {
	for name, test := range map[string]struct {
		responses map[string]testsupport.FakeResponse
		want      string
	}{
		"offline":                {map[string]testsupport.FakeResponse{}, "GitHub could not be reached"},
		"rate limited":           {map[string]testsupport.FakeResponse{ReleasesURL: {Status: 403}}, "HTTP 403 (GitHub allows 60 unauthenticated"},
		"not found":              {map[string]testsupport.FakeResponse{ReleasesURL: {Status: 404}}, "HTTP 404"},
		"cross-host redirect":    {map[string]testsupport.FakeResponse{ReleasesURL: {Location: "https://evil.example/releases"}}, "a redirect to https://evil.example was refused"},
		"plain HTTP redirect":    {map[string]testsupport.FakeResponse{ReleasesURL: {Location: "http://api.github.com/releases"}}, "a redirect to http://api.github.com was refused"},
		"other port redirect":    {map[string]testsupport.FakeResponse{ReleasesURL: {Location: "https://api.github.com:8443/releases"}}, "was refused"},
		"oversized announced":    {map[string]testsupport.FakeResponse{ReleasesURL: {Body: []byte("[]"), ContentLength: MaxReleasesBytes + 1}}, "larger than"},
		"oversized body":         {map[string]testsupport.FakeResponse{ReleasesURL: {Body: append([]byte("["), bytes.Repeat([]byte(" "), MaxReleasesBytes+1)...), ContentLength: -1}}, "larger than"},
		"malformed":              {map[string]testsupport.FakeResponse{ReleasesURL: {Body: []byte(`{"message":"x"}`)}}, "unexpected document"},
		"redirect to the reader": {map[string]testsupport.FakeResponse{ReleasesURL: {Location: "https://api.github.com/repos/georgejieh/open-trestle/releases?page=1"}, "https://api.github.com/repos/georgejieh/open-trestle/releases?page=1": {Body: []byte("[]")}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			fake := testsupport.NewFakeGitHub()
			for address, response := range test.responses {
				fake.Set(address, response)
			}
			releases, err := Client{Transport: fake}.Releases(context.Background(), time.Second)
			if test.want == "" {
				if err != nil || len(releases) != 0 {
					t.Fatalf("releases=%v err=%v", releases, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) || releases != nil {
				t.Fatalf("releases=%v err=%v, want %q", releases, err, test.want)
			}
			for _, request := range fake.Requests() {
				if strings.Contains(request.URL, "evil.example") || strings.HasPrefix(request.URL, "http://") || strings.Contains(request.URL, ":8443") {
					t.Fatalf("followed a refused redirect: %s", request.URL)
				}
			}
		})
	}
}

func TestDownloadFollowsOnlyGitHubAssetHosts(t *testing.T) {
	asset := Asset{URL: "https://github.com/georgejieh/open-trestle/releases/download/v0.2.0/" + ArchiveName, Size: 5}
	storage := "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sp=r"
	fake := testsupport.NewFakeGitHub()
	fake.Set(asset.URL, testsupport.FakeResponse{Location: storage})
	fake.Set(storage, testsupport.FakeResponse{Body: []byte("bytes")})
	var body bytes.Buffer
	if n, err := (Client{Transport: fake}).Download(context.Background(), asset, 5, time.Second, &body); err != nil || n != 5 || body.String() != "bytes" {
		t.Fatalf("n=%d err=%v body=%q", n, err, body.String())
	}
	// Over its bound, it stops.
	body.Reset()
	if _, err := (Client{Transport: fake}).Download(context.Background(), asset, 4, time.Second, &body); err == nil || !strings.Contains(err.Error(), "larger than 4 bytes") {
		t.Fatalf("err=%v", err)
	}
	// A redirect anywhere else is refused.
	fake.Set(asset.URL, testsupport.FakeResponse{Location: "https://downloads.example/archive"})
	if _, err := (Client{Transport: fake}).Download(context.Background(), asset, 5, time.Second, &body); err == nil || !strings.Contains(err.Error(), "a redirect to https://downloads.example was refused") {
		t.Fatalf("err=%v", err)
	}
	// Only this repository's release downloads are read at all.
	for _, address := range []string{"https://github.com/other/repo/releases/download/v0.2.0/" + ArchiveName, "https://objects.githubusercontent.com/x", "http://github.com/georgejieh/open-trestle/releases/download/v0.2.0/x"} {
		if _, err := (Client{Transport: fake}).Download(context.Background(), Asset{URL: address}, 5, time.Second, &body); err == nil {
			t.Fatalf("read %s", address)
		}
	}
	for _, request := range fake.Requests() {
		if strings.Contains(request.URL, "example") || strings.Contains(request.URL, "other/repo") || strings.HasPrefix(request.URL, "http://") {
			t.Fatalf("requested %s", request.URL)
		}
	}
}
