package s3

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func erasureTestVersionXML(key, id string, latest bool, metadata string) string {
	return "<Version><Key>" + erasureTestXMLText(key) + "</Key><VersionId>" + erasureTestXMLText(id) + "</VersionId><IsLatest>" + strconv.FormatBool(latest) + "</IsLatest><Size>0</Size>" + metadata + "</Version>"
}

func erasureTestMarkerXML(key, id string, latest bool) string {
	return "<DeleteMarker><Key>" + erasureTestXMLText(key) + "</Key><VersionId>" + erasureTestXMLText(id) + "</VersionId><IsLatest>" + strconv.FormatBool(latest) + "</IsLatest></DeleteMarker>"
}

func erasureTestListXML(limit uint16, keyMarker, versionMarker string, truncated bool, nextVersion, entries string) string {
	markers := "<KeyMarker>" + erasureTestXMLText(keyMarker) + "</KeyMarker><VersionIdMarker>" + erasureTestXMLText(versionMarker) + "</VersionIdMarker>"
	next := ""
	if truncated {
		next = "<NextKeyMarker>" + erasureTestKey + "</NextKeyMarker><NextVersionIdMarker>" + erasureTestXMLText(nextVersion) + "</NextVersionIdMarker>"
	}
	return fmt.Sprintf("<ListVersionsResult><Name>%s</Name><Prefix>%s</Prefix><MaxKeys>%d</MaxKeys><IsTruncated>%t</IsTruncated>%s%s%s</ListVersionsResult>", erasureTestBucket, erasureTestKey, limit, truncated, markers, next, entries)
}

func erasureTestListCase(t *testing.T, xml string, cursor artifact.VersionCursor, limit uint16, maximum uint32, check func(artifact.VersionPage, error)) {
	t.Helper()
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
		if index == 0 {
			return erasureTestReply{wire: erasureTestOperationWire("list")}
		}
		return erasureTestReply{wire: erasureTestWire(200, "", xml), close: true}
	})
	b := s.backend(t)
	erasureTestOperation(t, b, "list", true)
	page, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, cursor, limit, maximum)
	check(page, err)
	r := s.assertTraffic(t, 2)
	erasureTestSigned(t, r[0], "GET", "/"+erasureTestBucket, url.Values{"versions": {""}, "prefix": {erasureTestKey}, "max-keys": {"2"}}, true)
	query := url.Values{"versions": {""}, "prefix": {erasureTestKey}, "max-keys": {strconv.Itoa(int(limit))}}
	if cursor.KeyMarker != "" {
		query.Set("key-marker", cursor.KeyMarker)
		query.Set("version-id-marker", cursor.VersionIDMarker)
	}
	erasureTestSigned(t, r[1], "GET", "/"+erasureTestBucket, query, true)
	if r[1].headers.Get("X-Amz-Optional-Object-Attributes") != "" {
		t.Fatal("unrequested restore attributes")
	}
}

func TestErasureVersionPagesAreBoundedObservationsNotTerminalAuthority(t *testing.T) {
	metadata := "<Owner><ID>synthetic-canonical-owner-not-account-id</ID></Owner><ETag>&quot;not-a-digest&quot;</ETag><LastModified>" + time.Now().UTC().Format(time.RFC3339) + "</LastModified><StorageClass>STANDARD</StorageClass>"
	for _, algorithm := range []string{"CRC32", "CRC32C", "SHA1", "SHA256", "CRC64NVME"} {
		metadata += "<ChecksumAlgorithm>" + algorithm + "</ChecksumAlgorithm>"
	}
	metadata += "<ChecksumType>COMPOSITE</ChecksumType>"
	entry := erasureTestVersionXML(erasureTestKey, erasureTestVersion, true, metadata)
	marker := erasureTestMarkerXML(erasureTestKey, "historical-marker", false)
	for _, namespace := range []string{"", "http://s3.amazonaws.com/doc/2006-03-01/"} {
		xml := erasureTestListXML(2, "", "", false, "", entry+marker)
		if namespace != "" {
			xml = strings.Replace(xml, "<ListVersionsResult>", `<ListVersionsResult xmlns="`+namespace+`">`, 1)
		}
		xml = `<?xml version="1.0" encoding="UTF-8"?>` + xml
		erasureTestListCase(t, xml, artifact.VersionCursor{}, 2, 4096, func(page artifact.VersionPage, err error) {
			if err != nil || len(page.Entries) != 2 || page.Truncated || page.Next != (artifact.VersionCursor{}) || page.ResponseBytes != uint32(len(xml)) {
				t.Fatalf("complete observation: entries=%d err=%v", len(page.Entries), err)
			}
			if page.Entries[0].Version.Identity() != erasureTestObjectVersion(t, artifact.ObjectVersionData, erasureTestVersion).Identity() || !page.Entries[0].IsLatest {
				t.Fatal("data metadata mapping")
			}
			if page.Entries[1].Version.Identity() != erasureTestObjectVersion(t, artifact.ObjectVersionDeleteMarker, "historical-marker").Identity() || page.Entries[1].IsLatest {
				t.Fatal("delete-marker metadata mapping")
			}
		})
	}
	for _, entries := range []string{"", erasureTestVersionXML(erasureTestKey, erasureTestVersion, true, "")} {
		xml := erasureTestListXML(2, "", "", false, "", entries)
		erasureTestListCase(t, xml, artifact.VersionCursor{}, 2, 4096, func(page artifact.VersionPage, err error) {
			want := 0
			if entries != "" {
				want = 1
			}
			if err != nil || len(page.Entries) != want || page.Truncated || page.Next != (artifact.VersionCursor{}) {
				t.Fatalf("empty/singleton bounded observation: %v", err)
			}
		})
	}
	// A max-keys=2 singleton is only adapter metadata. Required fence identity and a fresh current read are core checks.
	first := erasureTestListXML(2, "", "", true, "opaque-next+/%2F=not-last", erasureTestVersionXML(erasureTestKey, "latest-data", true, ""))
	cursor := artifact.VersionCursor{KeyMarker: erasureTestKey, VersionIDMarker: "opaque-next+/%2F=not-last"}
	second := erasureTestListXML(2, cursor.KeyMarker, cursor.VersionIDMarker, false, "", erasureTestVersionXML(erasureTestKey, "older%2F+token", false, ""))
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
		if index == 0 {
			return erasureTestReply{wire: erasureTestWire(200, "", first)}
		}
		return erasureTestReply{wire: erasureTestWire(200, "", second)}
	})
	b := s.backend(t)
	p1, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, artifact.VersionCursor{}, 2, 4096)
	if err != nil || !p1.Truncated || p1.Next != cursor || len(p1.Entries) != 1 {
		t.Fatalf("short truncated page is not final: %v", err)
	}
	p2, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, p1.Next, 2, 4096)
	if err != nil || p2.Truncated || p2.Next != (artifact.VersionCursor{}) || len(p2.Entries) != 1 || p2.Entries[0].Version.VersionID() != "older%2F+token" || p2.Entries[0].IsLatest {
		t.Fatalf("opaque continuation observation: %v", err)
	}
	p1.Entries[0] = artifact.VersionEntry{}
	if p2.Entries[0].Version.VersionID() != "older%2F+token" {
		t.Fatal("page slices alias")
	}
	r := s.assertTraffic(t, 2)
	erasureTestSigned(t, r[0], "GET", "/"+erasureTestBucket, url.Values{"versions": {""}, "prefix": {erasureTestKey}, "max-keys": {"2"}}, true)
	erasureTestSigned(t, r[1], "GET", "/"+erasureTestBucket, url.Values{"versions": {""}, "prefix": {erasureTestKey}, "max-keys": {"2"}, "key-marker": {cursor.KeyMarker}, "version-id-marker": {cursor.VersionIDMarker}}, true)
}

func TestErasureVersionXMLStrictFieldsTypesAndExactKey(t *testing.T) {
	entry := erasureTestVersionXML(erasureTestKey, erasureTestVersion, true, "")
	base := erasureTestListXML(2, "", "", false, "", entry)
	replace := func(old, next string) string { return strings.Replace(base, old, next, 1) }
	cases := map[string]string{
		"wrong-bucket":             replace("<Name>"+erasureTestBucket+"</Name>", "<Name>other-bucket</Name>"),
		"wrong-prefix":             replace("<Prefix>"+erasureTestKey+"</Prefix>", "<Prefix>objects/</Prefix>"),
		"sibling-is-not-skipped":   replace("<Key>"+erasureTestKey+"</Key>", "<Key>"+erasureTestKey+".sibling</Key>"),
		"percent-not-url-decoded":  replace("<Key>"+erasureTestKey+"</Key>", "<Key>objects%2Ffixture.data</Key>"),
		"wrong-maxkeys":            replace("<MaxKeys>2</MaxKeys>", "<MaxKeys>3</MaxKeys>"),
		"maxkeys-type":             replace("<MaxKeys>2</MaxKeys>", "<MaxKeys>2.0</MaxKeys>"),
		"duplicate-name":           replace("</Name>", "</Name><Name>"+erasureTestBucket+"</Name>"),
		"missing-name":             replace("<Name>"+erasureTestBucket+"</Name>", ""),
		"duplicate-truncated":      replace("</IsTruncated>", "</IsTruncated><IsTruncated>false</IsTruncated>"),
		"boolean-numeric":          replace("<IsTruncated>false</IsTruncated>", "<IsTruncated>0</IsTruncated>"),
		"latest-uppercase":         replace("<IsLatest>true</IsLatest>", "<IsLatest>TRUE</IsLatest>"),
		"missing-latest":           replace("<IsLatest>true</IsLatest>", ""),
		"duplicate-version-id":     replace("</VersionId>", "</VersionId><VersionId>other</VersionId>"),
		"null-version":             replace(erasureTestVersion, "null"),
		"unicode-space-version":    replace(erasureTestVersion, "bad\u2003token"),
		"oversized-version":        replace(erasureTestVersion, strings.Repeat("v", 505)),
		"negative-size":            replace("<Size>0</Size>", "<Size>-1</Size>"),
		"fraction-size":            replace("<Size>0</Size>", "<Size>0.1</Size>"),
		"oversized-size":           replace("<Size>0</Size>", "<Size>33554433</Size>"),
		"missing-size":             replace("<Size>0</Size>", ""),
		"duplicate-size":           replace("<Size>0</Size>", "<Size>0</Size><Size>0</Size>"),
		"unknown-root-child":       replace("</ListVersionsResult>", "<Surprise/></ListVersionsResult>"),
		"unknown-entry-child":      replace("</Version>", "<Surprise/></Version>"),
		"unknown-root-attr":        replace("<ListVersionsResult>", `<ListVersionsResult surprise="yes">`),
		"unknown-entry-attr":       replace("<Version>", `<Version surprise="yes">`),
		"unknown-scalar-attr":      replace("<Key>", `<Key surprise="yes">`),
		"wrong-namespace":          replace("<ListVersionsResult>", `<ListVersionsResult xmlns="urn:wrong">`),
		"namespace-no-final-slash": replace("<ListVersionsResult>", `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">`),
		"mixed-namespace":          replace("<Version>", `<Version xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`),
		"DTD-entity":               `<!DOCTYPE ListVersionsResult [<!ENTITY x "opaque">]>` + base,
		"custom-entity":            replace(erasureTestVersion, "&custom;"),
		"processing-instruction":   `<?untrusted processing?>` + base,
		"trailing-junk":            base + "junk",
		"second-root":              base + base,
		"invalid-utf8":             replace(erasureTestVersion, string([]byte{255})),
		"partial-xml":              base[:len(base)-4],
		"owner-duplicate":          replace("</Version>", "<Owner><ID>x</ID></Owner><Owner><ID>x</ID></Owner></Version>"),
		"owner-missing-id":         replace("</Version>", "<Owner><DisplayName>x</DisplayName></Owner></Version>"),
		"owner-duplicate-id":       replace("</Version>", "<Owner><ID>x</ID><ID>x</ID></Owner></Version>"),
		"owner-too-large-decoded":  replace("</Version>", "<Owner><ID>"+strings.Repeat("&#x61;", 257)+"</ID></Owner></Version>"),
		"owner-control":            replace("</Version>", "<Owner><ID>x&#10;y</ID></Owner></Version>"),
		"display-too-large":        replace("</Version>", "<Owner><ID>x</ID><DisplayName>"+strings.Repeat("d", 257)+"</DisplayName></Owner></Version>"),
		"unknown-checksum":         replace("</Version>", "<ChecksumAlgorithm>SHA512</ChecksumAlgorithm></Version>"),
		"duplicate-checksum":       replace("</Version>", "<ChecksumAlgorithm>SHA256</ChecksumAlgorithm><ChecksumAlgorithm>SHA256</ChecksumAlgorithm></Version>"),
		"bad-checksum-type":        replace("</Version>", "<ChecksumType>INVENTED</ChecksumType></Version>"),
		"restore-status":           replace("</Version>", "<RestoreStatus><IsRestoreInProgress>false</IsRestoreInProgress></RestoreStatus></Version>"),
		"delimiter":                replace("</ListVersionsResult>", "<Delimiter>/</Delimiter></ListVersionsResult>"),
		"encoding-type":            replace("</ListVersionsResult>", "<EncodingType>url</EncodingType></ListVersionsResult>"),
		"common-prefixes":          replace("</ListVersionsResult>", "<CommonPrefixes><Prefix>neighbor/</Prefix></CommonPrefixes></ListVersionsResult>"),
		"duplicate-entry":          replace("</ListVersionsResult>", entry+"</ListVersionsResult>"),
		"same-id-cross-kind":       replace("</ListVersionsResult>", erasureTestMarkerXML(erasureTestKey, erasureTestVersion, false)+"</ListVersionsResult>"),
		"multiple-latest":          replace("</ListVersionsResult>", erasureTestMarkerXML(erasureTestKey, "other-token", true)+"</ListVersionsResult>"),
		"marker-size":              erasureTestListXML(2, "", "", false, "", strings.Replace(erasureTestMarkerXML(erasureTestKey, "marker", true), "</DeleteMarker>", "<Size>0</Size></DeleteMarker>", 1)),
		"marker-etag":              erasureTestListXML(2, "", "", false, "", strings.Replace(erasureTestMarkerXML(erasureTestKey, "marker", true), "</DeleteMarker>", "<ETag>x</ETag></DeleteMarker>", 1)),
		"marker-checksum":          erasureTestListXML(2, "", "", false, "", strings.Replace(erasureTestMarkerXML(erasureTestKey, "marker", true), "</DeleteMarker>", "<ChecksumAlgorithm>SHA256</ChecksumAlgorithm></DeleteMarker>", 1)),
	}
	for name, xml := range cases {
		t.Run(name, func(t *testing.T) {
			want := artifact.ErrRemoteObjectIntegrity
			if name == "owner-too-large-decoded" || name == "display-too-large" || name == "oversized-version" {
				want = artifact.ErrRemoteObjectTooLarge
			}
			erasureTestListCase(t, xml, artifact.VersionCursor{}, 2, 8192, func(page artifact.VersionPage, err error) {
				erasureTestZeroPage(t, page, err)
				if !errors.Is(err, want) {
					t.Fatalf("malformed200 mapping: %v want %v", err, want)
				}
			})
		})
	}
}

func TestErasureVersionCursorByteEntryAndNetworkBounds(t *testing.T) {
	entry := erasureTestVersionXML(erasureTestKey, erasureTestVersion, true, "")
	truncated := erasureTestListXML(2, "", "", true, "opaque-next", entry)
	for name, xml := range map[string]string{
		"empty-truncated":       erasureTestListXML(2, "", "", true, "opaque-next", ""),
		"missing-second-marker": strings.Replace(truncated, "<NextVersionIdMarker>opaque-next</NextVersionIdMarker>", "", 1),
		"cross-key-next":        strings.Replace(truncated, "<NextKeyMarker>"+erasureTestKey+"</NextKeyMarker>", "<NextKeyMarker>sibling</NextKeyMarker>", 1),
		"null-next-version":     strings.Replace(truncated, "opaque-next", "null", 1),
		"final-with-next":       strings.Replace(truncated, "<IsTruncated>true</IsTruncated>", "<IsTruncated>false</IsTruncated>", 1),
		"unexpected-echo":       strings.Replace(truncated, "<KeyMarker></KeyMarker>", "<KeyMarker>"+erasureTestKey+"</KeyMarker>", 1),
	} {
		t.Run(name, func(t *testing.T) {
			erasureTestListCase(t, xml, artifact.VersionCursor{}, 2, 4096, func(page artifact.VersionPage, err error) { erasureTestZeroPage(t, page, err) })
		})
	}
	cursor := artifact.VersionCursor{KeyMarker: erasureTestKey, VersionIDMarker: "supplied-opaque"}
	for _, xml := range []string{
		erasureTestListXML(2, cursor.KeyMarker, cursor.VersionIDMarker, true, cursor.VersionIDMarker, entry),
		erasureTestListXML(2, cursor.KeyMarker, "wrong-echo", false, "", entry),
	} {
		erasureTestListCase(t, xml, cursor, 2, 4096, func(page artifact.VersionPage, err error) { erasureTestZeroPage(t, page, err) })
	}
	for _, limit := range []uint16{1, 256} {
		var entries strings.Builder
		for i := 0; i < int(limit); i++ {
			entries.WriteString(erasureTestVersionXML(erasureTestKey, fmt.Sprintf("opaque-%d", i), i == 0, ""))
		}
		xml := erasureTestListXML(limit, "", "", false, "", entries.String())
		erasureTestListCase(t, xml, artifact.VersionCursor{}, limit, 1<<20, func(page artifact.VersionPage, err error) {
			if err != nil || len(page.Entries) != int(limit) || page.ResponseBytes != uint32(len(xml)) {
				t.Fatalf("entry boundary positive: %v", err)
			}
		})
		over := strings.Replace(xml, "</ListVersionsResult>", erasureTestMarkerXML(erasureTestKey, "overflow-token", false)+"</ListVersionsResult>", 1)
		erasureTestListCase(t, over, artifact.VersionCursor{}, limit, 1<<20, func(page artifact.VersionPage, err error) { erasureTestZeroPage(t, page, err) })
	}
	base := erasureTestListXML(2, "", "", false, "", entry)
	for _, cap := range []int{4096, 1 << 20} {
		for _, extra := range []int{0, 1} {
			xml := strings.Replace(base, "</ListVersionsResult>", strings.Repeat(" ", cap+extra-len(base))+"</ListVersionsResult>", 1)
			erasureTestListCase(t, xml, artifact.VersionCursor{}, 2, uint32(cap), func(page artifact.VersionPage, err error) {
				if extra == 0 {
					if err != nil || len(page.Entries) != 1 || page.ResponseBytes != uint32(cap) {
						t.Fatalf("raw XML cap positive: %v", err)
					}
				} else {
					erasureTestZeroPage(t, page, err)
					if !errors.Is(err, artifact.ErrRemoteObjectTooLarge) {
						t.Fatalf("raw XML cap mapping: %v", err)
					}
				}
			})
		}
	}
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, _ int) erasureTestReply {
		return erasureTestReply{wire: erasureTestOperationWire("list")}
	})
	b := s.backend(t)
	erasureTestOperation(t, b, "list", true)
	for _, limit := range []uint16{0, 257} {
		page, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, artifact.VersionCursor{}, limit, 4096)
		erasureTestZeroPage(t, page, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("limit preflight")
		}
	}
	for _, maximum := range []uint32{0, (1 << 20) + 1} {
		page, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, artifact.VersionCursor{}, 2, maximum)
		erasureTestZeroPage(t, page, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("byte preflight")
		}
	}
	for _, invalid := range []artifact.VersionCursor{{KeyMarker: erasureTestKey}, {VersionIDMarker: "opaque"}, {KeyMarker: "sibling", VersionIDMarker: "opaque"}, {KeyMarker: erasureTestKey, VersionIDMarker: "null"}} {
		page, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, invalid, 2, 4096)
		erasureTestZeroPage(t, page, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("cursor preflight")
		}
	}
	s.assertTraffic(t, 1)
	for _, wire := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(base)+4) + "\r\n\r\n" + base,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + strconv.FormatInt(int64(len(base)), 16) + "\r\n" + base + "\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Untrusted\r\n\r\n" + strconv.FormatInt(int64(len(base)), 16) + "\r\n" + base + "\r\n0\r\nX-Untrusted: x\r\n\r\n",
	} {
		s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
			if index == 0 {
				return erasureTestReply{wire: erasureTestOperationWire("list")}
			}
			return erasureTestReply{wire: wire, close: true}
		})
		b := s.backend(t)
		erasureTestOperation(t, b, "list", true)
		page, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, artifact.VersionCursor{}, 2, 4096)
		erasureTestZeroPage(t, page, err)
		s.assertTraffic(t, 2)
	}
	if reflect.DeepEqual(artifact.VersionPage{}, artifact.VersionPage{Entries: []artifact.VersionEntry{}}) {
		t.Fatal("fixture must distinguish true zero error outputs from allocated empty success slices")
	}
}
