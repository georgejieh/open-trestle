package s3

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestErasureExactMetadataUsesCanonicalIndependentIdentity(t *testing.T) {
	key := erasureTestExactKey(t)
	if key.NamespaceIdentity() != strings.Repeat("a", 64) || key.Key() != erasureTestKey || key.Validate() != nil {
		t.Fatal("exact-key fixture shape")
	}
	for _, kind := range []artifact.ObjectVersionKind{artifact.ObjectVersionData, artifact.ObjectVersionDeleteMarker} {
		v := erasureTestObjectVersion(t, kind, erasureTestVersion)
		wireKind := "data"
		if kind == artifact.ObjectVersionDeleteMarker {
			wireKind = "delete_marker"
		}
		preimage := struct {
			Contract          string `json:"contract"`
			SchemaVersion     int    `json:"schema_version"`
			NamespaceIdentity string `json:"namespace_identity"`
			Key               string `json:"key"`
			Kind              string `json:"kind"`
			VersionID         string `json:"version_id"`
		}{"open-trestle/artifact-object-version", 1, strings.Repeat("a", 64), erasureTestKey, wireKind, erasureTestVersion}
		canonical, err := json.Marshal(preimage)
		if err != nil {
			t.Fatal(err)
		}
		identity := erasureTestDigest(append([]byte("open-trestle/artifact-object-version/v1\x00"), canonical...))
		if v.Identity() != identity || v.Kind() != kind || v.VersionID() != erasureTestVersion || v.NamespaceIdentity() != key.NamespaceIdentity() || v.Key() != key.Key() || v.Validate() != nil {
			t.Fatal("version canonical identity/shape disagrees with independent preimage")
		}
		encoded, err := artifact.EncodeObjectVersion(v)
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Replace(canonical, []byte(`"schema_version":1,`), []byte(`"schema_version":1,"identity":"`+identity+`",`), 1)
		if !bytes.Equal(encoded, want) {
			t.Fatal("version encoding not canonical independent bytes")
		}
		parsed, err := artifact.ParseObjectVersion(want)
		if err != nil || parsed.Identity() != identity {
			t.Fatalf("public parse roundtrip: %v", err)
		}
	}
	if erasureTestObjectVersion(t, artifact.ObjectVersionData, erasureTestVersion).Identity() == erasureTestObjectVersion(t, artifact.ObjectVersionDeleteMarker, erasureTestVersion).Identity() {
		t.Fatal("data and marker identities collide")
	}
	for _, id := range []string{"", "null", "bad token", "x\u00a0y", "x\ny", strings.Repeat("v", 505), string([]byte{255})} {
		v, err := artifact.NewObjectVersion(key.NamespaceIdentity(), key.Key(), artifact.ObjectVersionData, id)
		if err == nil || !reflect.DeepEqual(v, artifact.ObjectVersion{}) {
			t.Fatal("invalid version minted")
		}
	}
	for _, raw := range []string{"", "/absolute", "a/../b", "a//b", "a/", "UPPER", "a?query"} {
		got, err := artifact.NewExactObjectKey(key.NamespaceIdentity(), raw)
		if err == nil || !reflect.DeepEqual(got, artifact.ExactObjectKey{}) {
			t.Fatal("invalid exact-key minted")
		}
	}
}

func TestErasureReadExclusiveObservationShapes(t *testing.T) {
	errorXML := `<Error><Code>NoSuchKey</Code><Message>synthetic absence</Message><RequestId>synthetic</RequestId><HostId>synthetic</HostId><Key>` + erasureTestKey + `</Key><Resource>/` + erasureTestBucket + `/` + erasureTestKey + `</Resource></Error>`
	cases := []struct {
		name          string
		status        int
		headers, body string
		kind          artifact.ErasureReadKind
	}{
		{"present", 200, "x-amz-version-id: " + erasureTestVersion + "\r\n", "complete-body", artifact.ErasureReadPresent},
		{"ordinary-absent", 404, "", errorXML, artifact.ErasureReadAbsent},
		{"marker-empty", 404, "X-AmZ-DeLeTe-MaRkEr: true\r\nx-amz-version-id: " + erasureTestVersion + "\r\n", "", artifact.ErasureReadCurrentDeleteMarker},
		{"marker-xml", 404, "x-amz-delete-marker: true\r\nx-amz-version-id: " + erasureTestVersion + "\r\n", errorXML, artifact.ErasureReadCurrentDeleteMarker},
		{"ordinary-namespace", 404, "", `<?xml version="1.0" encoding="UTF-8"?><Error xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Code>NoSuchKey</Code></Error>`, artifact.ErasureReadAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			erasureTestReadCase(t, erasureTestWire(tc.status, tc.headers, tc.body), 4096, func(got artifact.ErasureObjectRead, err error) {
				if err != nil || got.Kind != tc.kind {
					t.Fatalf("observation kind=%v err=%v", got.Kind, err)
				}
				if tc.kind == artifact.ErasureReadPresent {
					if string(got.Object.Content) != tc.body || got.Object.Digest != erasureTestDigest([]byte(tc.body)) || got.Object.Version != "version:"+erasureTestVersion || !reflect.DeepEqual(got.Marker, artifact.ObjectVersion{}) {
						t.Fatal("present shape")
					}
				} else {
					if !reflect.DeepEqual(got.Object, artifact.RemoteObject{}) {
						t.Fatal("absence/marker exposed content or digest")
					}
					if tc.kind == artifact.ErasureReadAbsent {
						if !reflect.DeepEqual(got.Marker, artifact.ObjectVersion{}) {
							t.Fatal("ordinary absence exposed marker")
						}
					} else if got.Marker.Identity() != erasureTestObjectVersion(t, artifact.ObjectVersionDeleteMarker, erasureTestVersion).Identity() {
						t.Fatal("marker not exact typed observation")
					}
				}
			})
		})
	}
	// No mutation follows a marker header. Authority/completion belongs to separately reserved core work.
}

func TestErasureReadHeaderStatusAndErrorXMLRefusals(t *testing.T) {
	version := "x-amz-version-id: " + erasureTestVersion + "\r\n"
	marker := "x-amz-delete-marker: true\r\n" + version
	cases := []struct {
		name          string
		status        int
		headers, body string
		want          error
	}{
		{"empty-body", 200, version, "", artifact.ErrRemoteObjectIntegrity},
		{"missing-version", 200, "", "body", artifact.ErrRemoteObjectIntegrity},
		{"null-version", 200, "x-amz-version-id: null\r\n", "body", artifact.ErrRemoteObjectIntegrity},
		{"empty-version", 200, "x-amz-version-id: \r\n", "body", artifact.ErrRemoteObjectIntegrity},
		{"duplicate-case-version", 200, version + "X-AmZ-VeRsIoN-Id: " + erasureTestVersion + "\r\n", "body", artifact.ErrRemoteObjectIntegrity},
		{"version-control", 200, "x-amz-version-id: bad token\r\n", "body", artifact.ErrRemoteObjectIntegrity},
		{"marker-on-200", 200, marker, "body", artifact.ErrRemoteObjectIntegrity},
		{"false-marker-on-200", 200, version + "x-amz-delete-marker: false\r\n", "body", artifact.ErrRemoteObjectIntegrity},
		{"protocol-switch", 101, "Connection: Upgrade\r\nUpgrade: websocket\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"partial-status", 206, version, "body", artifact.ErrRemoteObjectIntegrity},
		{"range-on-200", 200, version + "Content-Range: bytes 0-3/9\r\n", "body", artifact.ErrRemoteObjectIntegrity},
		{"gzip", 200, version + "Content-Encoding: gzip\r\n", "body", artifact.ErrRemoteObjectIntegrity},
		{"marker-versionless", 404, "x-amz-delete-marker: true\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"marker-null", 404, "x-amz-delete-marker: true\r\nx-amz-version-id: null\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"marker-comma-values", 404, version + "x-amz-delete-marker: true,true\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"marker-false", 404, version + "x-amz-delete-marker: false\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"marker-empty-header", 404, version + "x-amz-delete-marker: \r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"marker-duplicate-case", 404, marker + "X-AmZ-DeLeTe-MaRkEr: true\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"marker-duplicate-version", 404, marker + "X-AmZ-Version-Id: another\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"ordinary-version-header", 404, version, `<Error><Code>NoSuchKey</Code></Error>`, artifact.ErrRemoteObjectIntegrity},
		{"marker-range", 404, marker + "Content-Range: bytes 0-0/1\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"marker-encoding", 404, marker + "Content-Encoding: gzip\r\n", "", artifact.ErrRemoteObjectIntegrity},
		{"ordinary-empty", 404, "", "", ErrS3Request},
		{"marker-html", 404, marker, "<html>not evidence</html>", ErrS3Request},
		{"wrong-error-code", 404, "", `<Error><Code>AccessDenied</Code></Error>`, ErrS3Request},
		{"denied", 403, "", "", artifact.ErrErasureBlocked},
		{"method-not-allowed", 405, marker, "", artifact.ErrRemoteObjectConflict},
		{"conflict", 409, "", "", artifact.ErrRemoteObjectConflict},
		{"precondition", 412, "", "", artifact.ErrRemoteObjectConflict},
		{"server-error", 500, "", "", ErrS3Request},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			erasureTestReadCase(t, erasureTestWire(tc.status, tc.headers, tc.body), 4096, func(got artifact.ErasureObjectRead, err error) {
				erasureTestZeroRead(t, got, err)
				if !errors.Is(err, tc.want) {
					t.Fatalf("mapping %v, want %v", err, tc.want)
				}
			})
		})
	}
	base := `<Error><Code>NoSuchKey</Code></Error>`
	invalidXML := []string{
		strings.Replace(base, "</Error>", `<Code>NoSuchKey</Code></Error>`, 1),
		strings.Replace(base, "NoSuchKey", " NoSuchKey", 1),
		strings.Replace(base, "<Error>", `<Error surprise="yes">`, 1),
		strings.Replace(base, "<Error>", `<Error xmlns="urn:wrong">`, 1),
		strings.Replace(base, "<Code>", `<Code xmlns="urn:wrong">`, 1),
		strings.Replace(base, "</Error>", `<Unknown>x</Unknown></Error>`, 1),
		strings.Replace(base, "</Error>", `<Key>sibling</Key></Error>`, 1),
		strings.Replace(base, "</Error>", `<Resource>/wrong/key</Resource></Error>`, 1),
		strings.Replace(base, "</Error>", `<VersionId>not-for-NoSuchKey</VersionId></Error>`, 1),
		strings.Replace(base, "</Error>", `<Message><Nested>x</Nested></Message></Error>`, 1),
		strings.Replace(base, "</Error>", `<Message>`+strings.Repeat("a", 1025)+`</Message></Error>`, 1),
		strings.Replace(base, "</Error>", `<RequestId>x</RequestId><RequestId>x</RequestId></Error>`, 1),
		`<!DOCTYPE Error [<!ENTITY x "NoSuchKey">]><Error><Code>&x;</Code></Error>`,
		`<?other forbidden?>` + base,
		`<?xml version="1.1"?>` + base,
		`<!--not allowed-->` + base,
		base + base,
		base + "junk",
		base[:len(base)-1],
		"<Error><Code>NoSuchKey</Code><Message>" + string([]byte{255}) + "</Message></Error>",
	}
	for i, body := range invalidXML {
		t.Run("strict-error-xml-"+strconv.Itoa(i), func(t *testing.T) {
			erasureTestReadCase(t, erasureTestWire(404, "", body), 4096, func(got artifact.ErasureObjectRead, err error) { erasureTestZeroRead(t, got, err) })
		})
	}
}

func TestErasureReadWholeBodyChecksumProfile(t *testing.T) {
	body := "complete-body"
	digest, _ := hex.DecodeString(erasureTestDigest([]byte(body)))
	sum := base64.StdEncoding.EncodeToString(digest)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, sum[len(sum)-2])
	noncanonical := sum[:len(sum)-2] + string(alphabet[last|1]) + "="
	cases := []struct {
		name, headers string
		valid         bool
	}{
		{"none-local-still-mandatory", "", true},
		{"full-object-pair", "x-amz-checksum-sha256: " + sum + "\r\nx-amz-checksum-type: FULL_OBJECT\r\n", true},
		{"sha-only", "x-amz-checksum-sha256: " + sum + "\r\n", false},
		{"type-only", "x-amz-checksum-type: FULL_OBJECT\r\n", false},
		{"composite", "x-amz-checksum-sha256: " + sum + "\r\nx-amz-checksum-type: COMPOSITE\r\n", false},
		{"wrong-local-digest", "x-amz-checksum-sha256: " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\r\nx-amz-checksum-type: FULL_OBJECT\r\n", false},
		{"wrong-length", "x-amz-checksum-sha256: eA==\r\nx-amz-checksum-type: FULL_OBJECT\r\n", false},
		{"noncanonical-base64-padding", "x-amz-checksum-sha256: " + noncanonical + "\r\nx-amz-checksum-type: FULL_OBJECT\r\n", false},
		{"malformed", "x-amz-checksum-sha256: !!!\r\nx-amz-checksum-type: FULL_OBJECT\r\n", false},
		{"empty", "x-amz-checksum-sha256: \r\nx-amz-checksum-type: FULL_OBJECT\r\n", false},
		{"duplicate-case", "x-amz-checksum-sha256: " + sum + "\r\nX-AmZ-Checksum-Sha256: " + sum + "\r\nx-amz-checksum-type: FULL_OBJECT\r\n", false},
		{"duplicate-type", "x-amz-checksum-sha256: " + sum + "\r\nx-amz-checksum-type: FULL_OBJECT\r\nX-Amz-Checksum-Type: FULL_OBJECT\r\n", false},
	}
	for _, algorithm := range []string{"crc32", "crc32c", "sha1", "crc64nvme", "sha512", "md5", "xxhash64", "unknown"} {
		cases = append(cases, struct {
			name, headers string
			valid         bool
		}{"unsupported-" + algorithm, "x-amz-checksum-" + algorithm + ": AAAA\r\n", false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			erasureTestReadCase(t, erasureTestWire(200, "x-amz-version-id: "+erasureTestVersion+"\r\n"+tc.headers, body), 4096, func(got artifact.ErasureObjectRead, err error) {
				if tc.valid {
					if err != nil || got.Kind != artifact.ErasureReadPresent || got.Object.Digest != erasureTestDigest([]byte(body)) || string(got.Object.Content) != body {
						t.Fatalf("complete local digest mandatory: %v", err)
					}
				} else {
					erasureTestZeroRead(t, got, err)
					if !errors.Is(err, artifact.ErrRemoteObjectIntegrity) {
						t.Fatalf("checksum mapping: %v", err)
					}
				}
			})
		})
	}
}

func TestErasureReadBoundsEOFAndTrailerPriority(t *testing.T) {
	for _, n := range []int{4096, 4097} {
		t.Run("body-"+strconv.Itoa(n), func(t *testing.T) {
			body := strings.Repeat("b", n)
			erasureTestReadCase(t, erasureTestWire(200, "x-amz-version-id: token\r\n", body), 4096, func(got artifact.ErasureObjectRead, err error) {
				if n == 4096 {
					if err != nil || len(got.Object.Content) != n || got.Object.Digest != erasureTestDigest([]byte(body)) {
						t.Fatalf("exact cap positive: %v", err)
					}
				} else {
					erasureTestZeroRead(t, got, err)
					if !errors.Is(err, artifact.ErrRemoteObjectTooLarge) {
						t.Fatalf("overflow mapping: %v", err)
					}
				}
			})
		})
	}
	base := `<Error><Code>NoSuchKey</Code></Error>`
	for _, n := range []int{4096, 4097} {
		body := strings.Replace(base, "</Error>", strings.Repeat(" ", n-len(base))+"</Error>", 1)
		erasureTestReadCase(t, erasureTestWire(404, "x-amz-delete-marker: true\r\nx-amz-version-id: token\r\n", body), 8192, func(got artifact.ErasureObjectRead, err error) {
			if n == 4096 {
				if err != nil || got.Kind != artifact.ErasureReadCurrentDeleteMarker {
					t.Fatalf("4096 error-body positive: %v", err)
				}
			} else {
				erasureTestZeroRead(t, got, err)
				if !errors.Is(err, artifact.ErrRemoteObjectTooLarge) {
					t.Fatalf("error-body cap must remain4096: %v", err)
				}
			}
		})
	}
	cases := []struct {
		wire string
		want error
	}{
		{erasureTestWire(200, "x-amz-version-id: token\r\nX-Large: "+strings.Repeat("h", 17000)+"\r\n", "body"), ErrS3Request},
		{"HTTP/1.1 200 OK\r\nx-amz-version-id: token\r\nContent-Length: 20\r\n\r\nprefix", ErrS3Request},
		{"HTTP/1.1 404 Not Found\r\nx-amz-delete-marker: true\r\nx-amz-version-id: token\r\nContent-Length: 4\r\n\r\n", ErrS3Request},
		{"HTTP/1.1 403 Forbidden\r\nContent-Length: 20\r\n\r\nshort", ErrS3Request},
		{"HTTP/1.1 200 OK\r\nx-amz-version-id: token\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n" + strings.Repeat("b", 4097) + "\r\n0\r\n\r\n", artifact.ErrRemoteObjectTooLarge},
		{"HTTP/1.1 200 OK\r\nx-amz-version-id: token\r\nTransfer-Encoding: chunked\r\nTrailer: X-Synthetic\r\n\r\n4\r\nbody\r\n0\r\nX-Synthetic: extra\r\n\r\n", artifact.ErrRemoteObjectIntegrity},
		{"HTTP/1.1 404 Not Found\r\nx-amz-delete-marker: true\r\nx-amz-version-id: token\r\nTransfer-Encoding: chunked\r\nTrailer: X-Synthetic\r\n\r\n0\r\nX-Synthetic: extra\r\n\r\n", artifact.ErrRemoteObjectIntegrity},
	}
	for _, tc := range cases {
		erasureTestReadCase(t, tc.wire, 4096, func(got artifact.ErasureObjectRead, err error) {
			erasureTestZeroRead(t, got, err)
			if !errors.Is(err, tc.want) {
				t.Fatalf("body failure priority: %v want %v", err, tc.want)
			}
		})
	}
}

func TestErasureConditionalCreateExactSignedBytesAndOutcomes(t *testing.T) {
	cases := []struct {
		status  int
		created bool
		want    error
	}{{200, true, nil}, {201, true, nil}, {412, false, nil}, {409, false, artifact.ErrRemoteObjectConflict}, {403, false, artifact.ErrErasureBlocked}, {405, false, artifact.ErrRemoteObjectConflict}, {500, false, ErrS3Request}}
	for _, tc := range cases {
		t.Run("status-"+strconv.Itoa(tc.status), func(t *testing.T) {
			s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
				if index == 0 {
					return erasureTestReply{wire: erasureTestWire(200, "", "")}
				}
				return erasureTestReply{wire: erasureTestWire(tc.status, "", "")}
			})
			b := s.backend(t)
			erasureTestOperation(t, b, "create", true)
			body := []byte("exact-canonical-content-not-inferred-from-bool")
			ok, err := b.CreateErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, body, erasureTestDigest(body))
			if ok != tc.created || !errors.Is(err, tc.want) {
				t.Fatalf("create status mapping: %t %v", ok, err)
			}
			erasureTestFixedError(t, err)
			requests := s.assertTraffic(t, 2)
			if !bytes.Equal(requests[1].body, body) {
				t.Fatal("create transmitted different body bytes")
			}
			for _, r := range requests {
				erasureTestSigned(t, r, "PUT", "/"+erasureTestBucket+"/"+erasureTestKey, nil, true)
				if r.headers.Get("If-None-Match") != "*" || r.headers.Get("Content-Type") != "application/octet-stream" {
					t.Fatal("conditional create shape")
				}
				digest, _ := hex.DecodeString(erasureTestDigest(r.body))
				if r.headers.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(digest) {
					t.Fatal("body checksum header mismatch")
				}
			}
		})
	}
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, _ int) erasureTestReply {
		return erasureTestReply{wire: erasureTestWire(201, "", "")}
	})
	b := s.backend(t)
	erasureTestOperation(t, b, "create", true)
	capBody := bytes.Repeat([]byte("b"), 16384)
	capOK, capErr := b.CreateErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, capBody, erasureTestDigest(capBody))
	if !capOK || capErr != nil {
		t.Fatalf("create body cap positive: %v", capErr)
	}
	for _, owner := range []string{"", "000000000000", "12345678901", "12345678901x"} {
		ok, err := b.CreateErasureObject(erasureTestContext(t), erasureTestExactKey(t), owner, []byte("x"), erasureTestDigest([]byte("x")))
		if ok || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("owner preflight: %v", err)
		}
	}
	for _, body := range [][]byte{nil, {}, bytes.Repeat([]byte("b"), 16385)} {
		ok, err := b.CreateErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, body, erasureTestDigest(body))
		if ok || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("body preflight: %v", err)
		}
	}
	ok, err := b.CreateErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, []byte("x"), erasureTestDigest([]byte("y")))
	if ok || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("digest preflight: %v", err)
	}
	s.assertTraffic(t, 2)
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation+"-response-overflow", func(t *testing.T) {
			s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
				if index == 0 {
					return erasureTestReply{wire: erasureTestOperationWire(operation)}
				}
				return erasureTestReply{wire: erasureTestWire(200, "", strings.Repeat("x", 4097)), close: true}
			})
			b := s.backend(t)
			erasureTestOperation(t, b, operation, true)
			err := erasureTestOperation(t, b, operation, false)
			if !errors.Is(err, artifact.ErrRemoteObjectTooLarge) {
				t.Fatalf("mutation response cap: %v", err)
			}
			erasureTestFixedError(t, err)
			s.assertTraffic(t, 2)
		})
	}
}

func TestErasureTypedDeleteExactVersionOnly(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		notFound bool
		want     error
	}{
		{"deleted200", 200, "", false, nil}, {"deleted204", 204, "", false, nil},
		{"not-found", 404, `<Error><Code>NoSuchVersion</Code><Key>` + erasureTestKey + `</Key><Resource>/` + erasureTestBucket + `/` + erasureTestKey + `</Resource><VersionId>` + erasureTestVersion + `</VersionId></Error>`, true, nil},
		{"generic404", 404, "", false, ErrS3Request}, {"wrong404", 404, `<Error><Code>NoSuchKey</Code></Error>`, false, ErrS3Request},
		{"wrong-version", 404, `<Error><Code>NoSuchVersion</Code><VersionId>other</VersionId></Error>`, false, ErrS3Request},
		{"conflict", 409, "", false, artifact.ErrRemoteObjectConflict}, {"precondition", 412, "", false, artifact.ErrRemoteObjectConflict}, {"blocked", 403, "", false, artifact.ErrErasureBlocked},
	}
	for _, kind := range []artifact.ObjectVersionKind{artifact.ObjectVersionData, artifact.ObjectVersionDeleteMarker} {
		for _, tc := range cases {
			t.Run(tc.name+"/"+strconv.Itoa(int(kind)), func(t *testing.T) {
				s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
					if index == 0 {
						return erasureTestReply{wire: erasureTestWire(204, "", "")}
					}
					return erasureTestReply{wire: erasureTestWire(tc.status, "", tc.body)}
				})
				b := s.backend(t)
				erasureTestOperation(t, b, "delete", true)
				got, err := b.DeleteObjectVersion(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, erasureTestObjectVersion(t, kind, erasureTestVersion))
				if !errors.Is(err, tc.want) {
					t.Fatalf("delete mapping: %v", err)
				}
				erasureTestFixedError(t, err)
				if tc.want != nil {
					if got != 0 {
						t.Fatal("delete error exposed outcome")
					}
				} else if tc.notFound {
					if got != artifact.VersionDeleteNotFound {
						t.Fatal("wrong not-found observation")
					}
				} else if got != artifact.VersionDeleteDeleted {
					t.Fatal("wrong deleted observation")
				}
				for _, r := range s.assertTraffic(t, 2) {
					erasureTestSigned(t, r, "DELETE", "/"+erasureTestBucket+"/"+erasureTestKey, url.Values{"versionId": []string{erasureTestVersion}}, true)
					if len(r.body) != 0 {
						t.Fatal("delete sent body/DeleteObjects")
					}
				}
			})
		}
	}
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, _ int) erasureTestReply {
		return erasureTestReply{wire: erasureTestWire(204, "", "")}
	})
	b := s.backend(t)
	erasureTestOperation(t, b, "delete", true)
	otherKey, err := artifact.NewObjectVersion(strings.Repeat("a", 64), "objects/sibling", artifact.ObjectVersionData, erasureTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	otherNS, err := artifact.NewObjectVersion(strings.Repeat("b", 64), erasureTestKey, artifact.ObjectVersionData, erasureTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []artifact.ObjectVersion{{}, otherKey, otherNS} {
		got, err := b.DeleteObjectVersion(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, v)
		if got != 0 || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("delete preflight exact binding: %v", err)
		}
	}
	s.assertTraffic(t, 1)
}
