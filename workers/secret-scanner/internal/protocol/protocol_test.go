package protocol

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

const fixtureRulesetIdentity = RulesetIdentity

func fixtureRequest() Request {
	return Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("0123456789abcdef", 4),
		Sources: []Source{{
			Ordinal: 0,
			Content: []byte("prefix TOKEN suffix\n"),
		}},
	}
}

func fixtureExpectation() ResponseExpectation {
	return ResponseExpectation{
		Request:         fixtureRequest(),
		RulesetIdentity: fixtureRulesetIdentity,
		RuleIDs:         map[string]struct{}{"github-pat": {}},
	}
}

func fixtureResponse() Response {
	match := Match{SourceOrdinal: 0, RuleID: "github-pat", StartByte: 7, EndByteExclusive: 12}
	match.OccurrenceID = OccurrenceID(match)
	return Response{
		SchemaVersion:   1,
		RequestID:       fixtureRequest().RequestID,
		Status:          StatusComplete,
		Scanner:         ScannerName,
		ScannerVersion:  ScannerVersion,
		ScannerCommit:   ScannerCommit,
		RulesetIdentity: fixtureRulesetIdentity,
		BuildProfile:    BuildProfile,
		Matches:         []Match{match},
	}
}

func TestFrozenBetterleaksIdentity(t *testing.T) {
	if ScannerName != "betterleaks" || ScannerVersion != "v1.8.1" || ScannerCommit != "5eab48332cc48565864514e3bc6de89df091a7c4" {
		t.Fatal("unexpected scanner identity")
	}
	if RulesetIdentity != "27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42" || RulesetRuleCount != 417 {
		t.Fatal("unexpected ruleset identity")
	}
	if BuildProfile != "public_detect_run_re2_purego_go1.26.11_linux_amd64_v1" {
		t.Fatal("unexpected build profile")
	}
	match := Match{SourceOrdinal: 0, RuleID: "github-pat", StartByte: 7, EndByteExclusive: 12}
	if got := OccurrenceID(match); got != "cc35a127e9e7243eb1e2d31391846f5e9288155b136915656fffce5caf594fd4" {
		t.Fatalf("unexpected occurrence ID: %s", got)
	}
}

func TestKnownBuildProfilesAreExactlyCurrentAndRecordedGo12610(t *testing.T) {
	for profile, want := range map[string]bool{
		"public_detect_run_re2_purego_go1.26.11_linux_amd64_v1": true,
		"public_detect_run_re2_purego_go1.26.10_linux_amd64_v1": true,
		"public_detect_run_re2_purego_go1.26.8_linux_amd64_v1":  false,
		"public_detect_run_re2_purego_go1.26.12_linux_amd64_v1": false,
		"": false,
	} {
		if got := KnownBuildProfile(profile); got != want {
			t.Fatalf("KnownBuildProfile(%q) = %v, want %v", profile, got, want)
		}
	}
}

func TestRecordedGo12610ResponseReadsBackByteForByte(t *testing.T) {
	recorded := readFixture(t, "response-v1-go1.26.10.json")
	response, err := ParseResponseFrame(frame(recorded), fixtureExpectation())
	if err != nil || response.BuildProfile != "public_detect_run_re2_purego_go1.26.10_linux_amd64_v1" {
		t.Fatalf("recorded go1.26.10 response did not read back: %v", err)
	}
	encoded, err := EncodeResponseFrame(response, fixtureExpectation())
	if err != nil || !bytes.Equal(encoded, frame(recorded)) {
		t.Fatalf("recorded go1.26.10 response changed on re-encode: %v", err)
	}
	if !bytes.Contains(readFixture(t, "response-v1.json"), []byte(`"build_profile":"`+BuildProfile+`"`)) {
		t.Fatal("canonical response fixture does not carry the current build profile")
	}
}

func frame(payload []byte) []byte {
	encoded := make([]byte, framePrefixBytes+len(payload))
	binary.BigEndian.PutUint32(encoded, uint32(len(payload)))
	copy(encoded[framePrefixBytes:], payload)
	return encoded
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestCanonicalProtocolFixturesRoundTrip(t *testing.T) {
	requestJSON := readFixture(t, "request-v1.json")
	request, err := ParseRequestFrame(frame(requestJSON))
	if err != nil {
		t.Fatal(err)
	}
	encodedRequest, err := EncodeRequestFrame(request)
	if err != nil || !bytes.Equal(encodedRequest, frame(requestJSON)) {
		t.Fatalf("request round trip differs: %v", err)
	}

	responseJSON := readFixture(t, "response-v1.json")
	for _, forbidden := range [][]byte{
		[]byte("TOKEN"),
		[]byte("VE9LRU4="),
		[]byte("cHJlZml4IFRPS0VOIHN1ZmZpeAo="),
		[]byte(`"snippet"`),
		[]byte(`"groups"`),
		[]byte(`"finding_id"`),
	} {
		if bytes.Contains(responseJSON, forbidden) {
			t.Fatalf("response fixture contains secret-bearing value or field %q", forbidden)
		}
	}
	response, err := ParseResponseFrame(frame(responseJSON), fixtureExpectation())
	if err != nil {
		t.Fatal(err)
	}
	encodedResponse, err := EncodeResponseFrame(response, fixtureExpectation())
	if err != nil || !bytes.Equal(encodedResponse, frame(responseJSON)) {
		t.Fatalf("response round trip differs: %v", err)
	}
}

func TestRequestProtocolRejectsNoncanonicalOrUnboundedInput(t *testing.T) {
	valid, err := EncodeRequestFrame(fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	payload := valid[framePrefixBytes:]
	cases := map[string][]byte{
		"zero length":          {0, 0, 0, 0},
		"truncated prefix":     {0, 0, 0},
		"truncated payload":    valid[:len(valid)-1],
		"trailing byte":        append(append([]byte{}, valid...), 0),
		"second frame":         append(append([]byte{}, valid...), valid...),
		"unknown field":        frame(bytes.Replace(payload, []byte(`"sources":`), []byte(`"unknown":false,"sources":`), 1)),
		"noncanonical spacing": frame(append([]byte{' '}, payload...)),
		"noncanonical order":   frame([]byte(`{"request_id":"` + fixtureRequest().RequestID + `","schema_version":1,"sources":[{"ordinal":0,"content_base64":"cHJlZml4IFRPS0VOIHN1ZmZpeAo="}]}`)),
		"invalid JSON UTF-8":   frame([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
		"invalid source UTF-8": frame([]byte(`{"schema_version":1,"request_id":"` + fixtureRequest().RequestID + `","sources":[{"ordinal":0,"content_base64":"/w=="}]}`)),
		"oversized frame":      append([]byte{0, 48, 0, 1}, make([]byte, maxRequestFrameBytes+1)...),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequestFrame(encoded); err == nil {
				t.Fatal("invalid request frame accepted")
			}
		})
	}

	invalid := map[string]Request{
		"schema version":       fixtureRequest(),
		"request ID":           fixtureRequest(),
		"no sources":           fixtureRequest(),
		"too many sources":     fixtureRequest(),
		"ordinal gap":          fixtureRequest(),
		"source too large":     fixtureRequest(),
		"aggregate too large":  fixtureRequest(),
		"source invalid UTF-8": fixtureRequest(),
	}
	changed := invalid["schema version"]
	changed.SchemaVersion = 2
	invalid["schema version"] = changed
	changed = invalid["request ID"]
	changed.RequestID = strings.Repeat("A", 64)
	invalid["request ID"] = changed
	changed = invalid["no sources"]
	changed.Sources = []Source{}
	invalid["no sources"] = changed
	changed = invalid["too many sources"]
	changed.Sources = make([]Source, maxSources+1)
	for index := range changed.Sources {
		changed.Sources[index].Ordinal = index
	}
	invalid["too many sources"] = changed
	changed = invalid["ordinal gap"]
	changed.Sources[0].Ordinal = 1
	invalid["ordinal gap"] = changed
	changed = invalid["source too large"]
	changed.Sources[0].Content = make([]byte, maxSourceBytes+1)
	invalid["source too large"] = changed
	changed = invalid["aggregate too large"]
	changed.Sources = make([]Source, maxAggregateSourceBytes/maxSourceBytes+1)
	for index := range changed.Sources {
		changed.Sources[index] = Source{Ordinal: index, Content: make([]byte, maxSourceBytes)}
	}
	invalid["aggregate too large"] = changed
	changed = invalid["source invalid UTF-8"]
	changed.Sources[0].Content = []byte{0xff}
	invalid["source invalid UTF-8"] = changed
	for name, request := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeRequestFrame(request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}

	for name, content := range map[string]string{
		"unpadded":         "YQ",
		"URL alphabet":     "____",
		"embedded newline": "YQ==\\n",
	} {
		t.Run("base64 "+name, func(t *testing.T) {
			changed := bytes.Replace(payload, []byte(`cHJlZml4IFRPS0VOIHN1ZmZpeAo=`), []byte(content), 1)
			if _, err := ParseRequestFrame(frame(changed)); err == nil {
				t.Fatal("noncanonical base64 accepted")
			}
		})
	}
}

func TestResponseProtocolRejectsInvalidMetadataMatchesAndSpans(t *testing.T) {
	expectation := fixtureExpectation()
	valid, err := EncodeResponseFrame(fixtureResponse(), expectation)
	if err != nil {
		t.Fatal(err)
	}
	payload := valid[framePrefixBytes:]
	framingCases := map[string][]byte{
		"zero length":          {0, 0, 0, 0},
		"trailing byte":        append(append([]byte{}, valid...), 0),
		"second frame":         append(append([]byte{}, valid...), valid...),
		"unknown field":        frame(bytes.Replace(payload, []byte(`"matches":`), []byte(`"error":"secret","matches":`), 1)),
		"secret match field":   frame(bytes.Replace(payload, []byte(`"start_byte":`), []byte(`"snippet":"TOKEN","start_byte":`), 1)),
		"noncanonical spacing": frame(append([]byte{' '}, payload...)),
		"invalid JSON UTF-8":   frame([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
		"oversized frame":      append([]byte{0, 64, 0, 1}, make([]byte, maxResponseFrameBytes+1)...),
	}
	for name, encoded := range framingCases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseResponseFrame(encoded, expectation); err == nil {
				t.Fatal("invalid response frame accepted")
			}
		})
	}

	invalid := map[string]Response{}
	set := func(name string, mutate func(*Response)) {
		response := fixtureResponse()
		mutate(&response)
		invalid[name] = response
	}
	set("schema version", func(response *Response) { response.SchemaVersion = 2 })
	set("request ID", func(response *Response) { response.RequestID = strings.Repeat("f", 64) })
	set("status", func(response *Response) { response.Status = "partial" })
	set("scanner", func(response *Response) { response.Scanner = "other" })
	set("retired scanner", func(response *Response) { response.Scanner = "ti" + "tus" })
	set("scanner version", func(response *Response) { response.ScannerVersion = "v0" })
	set("retired scanner version", func(response *Response) { response.ScannerVersion = "v1." + "2.10" })
	set("scanner commit", func(response *Response) { response.ScannerCommit = strings.Repeat("0", 40) })
	set("retired scanner commit", func(response *Response) {
		response.ScannerCommit = "f2c9e1f5c090c27f43bd" + "eb7b49546b59c86aa508"
	})
	set("ruleset identity", func(response *Response) { response.RulesetIdentity = strings.Repeat("b", 64) })
	set("build profile", func(response *Response) { response.BuildProfile = "native" })
	set("unrecorded earlier Go patch profile", func(response *Response) {
		response.BuildProfile = "public_detect_run_re2_purego_go1.26.8_linux_amd64_v1"
	})
	set("unreviewed later Go patch profile", func(response *Response) {
		response.BuildProfile = "public_detect_run_re2_purego_go1.26.12_linux_amd64_v1"
	})
	set("retired build profile", func(response *Response) { response.BuildProfile = "pure_go_" + "linux_amd64_v1" })
	set("nil matches", func(response *Response) { response.Matches = nil })
	set("unknown rule", func(response *Response) {
		response.Matches[0].RuleID = "unknown"
		response.Matches[0].OccurrenceID = OccurrenceID(response.Matches[0])
	})
	set("missing source", func(response *Response) {
		response.Matches[0].SourceOrdinal = 1
		response.Matches[0].OccurrenceID = OccurrenceID(response.Matches[0])
	})
	set("zero width", func(response *Response) {
		response.Matches[0].EndByteExclusive = response.Matches[0].StartByte
		response.Matches[0].OccurrenceID = OccurrenceID(response.Matches[0])
	})
	set("out of range", func(response *Response) {
		response.Matches[0].EndByteExclusive = 100
		response.Matches[0].OccurrenceID = OccurrenceID(response.Matches[0])
	})
	set("invalid occurrence", func(response *Response) { response.Matches[0].OccurrenceID = strings.Repeat("0", 64) })
	set("matches on failure", func(response *Response) { response.Status = StatusScanFailed })
	set("too many matches", func(response *Response) { response.Matches = make([]Match, maxMatches+1) })
	for name, response := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeResponseFrame(response, expectation); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	wrongRuleset := expectation
	wrongRuleset.RulesetIdentity = strings.Repeat("b", 64)
	if _, err := EncodeResponseFrame(fixtureResponse(), wrongRuleset); err == nil {
		t.Fatal("response accepted with an unpinned expected ruleset")
	}
}

func TestResponseProtocolRejectsNoncanonicalOrderDuplicatesAndSplitUTF8(t *testing.T) {
	request := fixtureRequest()
	request.Sources[0].Content = []byte("aβz")
	request.Sources = append(request.Sources, Source{Ordinal: 1, Content: []byte("aβz")})
	expectation := fixtureExpectation()
	expectation.Request = request
	expectation.RuleIDs["alpha"] = struct{}{}
	expectation.RuleIDs["omega"] = struct{}{}
	makeMatch := func(source, start, end int, rule string) Match {
		match := Match{SourceOrdinal: source, RuleID: rule, StartByte: start, EndByteExclusive: end}
		match.OccurrenceID = OccurrenceID(match)
		return match
	}
	response := fixtureResponse()
	response.RequestID = request.RequestID

	for name, matches := range map[string][]Match{
		"split start":  {makeMatch(0, 2, 3, "github-pat")},
		"split end":    {makeMatch(0, 1, 2, "github-pat")},
		"duplicate":    {makeMatch(0, 1, 3, "github-pat"), makeMatch(0, 1, 3, "github-pat")},
		"source order": {makeMatch(1, 0, 1, "github-pat"), makeMatch(0, 0, 1, "github-pat")},
		"start order":  {makeMatch(0, 3, 4, "github-pat"), makeMatch(0, 0, 1, "github-pat")},
		"end order":    {makeMatch(0, 0, 3, "github-pat"), makeMatch(0, 0, 1, "github-pat")},
		"rule order":   {makeMatch(0, 0, 1, "omega"), makeMatch(0, 0, 1, "alpha")},
	} {
		t.Run(name, func(t *testing.T) {
			response.Matches = matches
			if _, err := EncodeResponseFrame(response, expectation); err == nil {
				t.Fatal("invalid matches accepted")
			}
		})
	}

	response.Matches = []Match{
		makeMatch(0, 0, 1, "alpha"),
		makeMatch(0, 0, 1, "omega"),
		makeMatch(0, 0, 3, "github-pat"),
		makeMatch(1, 0, 1, "github-pat"),
	}
	encoded, err := EncodeResponseFrame(response, expectation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponseFrame(encoded, expectation); err != nil {
		t.Fatal(err)
	}
}

func TestResponseProtocolAcceptsEveryClosedStatusWithoutMatches(t *testing.T) {
	for _, status := range []string{StatusComplete, StatusInputRejected, StatusScanFailed, StatusResourceExhausted} {
		t.Run(status, func(t *testing.T) {
			response := fixtureResponse()
			response.Status = status
			response.Matches = []Match{}
			encoded, err := EncodeResponseFrame(response, fixtureExpectation())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseResponseFrame(encoded, fixtureExpectation()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
