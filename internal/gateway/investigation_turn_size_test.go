package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const (
	turnSizeRequestLimit          = 8 << 20
	turnSizeResponseLimit         = 8 << 20
	turnSizePartLimit             = 2 << 20
	turnSizePartCount             = 64
	turnSizeArtifactPayloadLimit  = 16 << 20
	turnSizeMetadataCeiling       = 941298
	turnSizeResponseBase64Ceiling = 11185064
)

// This oracle reads host wire types, not the estimator's parsed shape or helper.
func turnSizeMetadataOracle(t *testing.T, value reflect.Type, name string, tag reflect.StructTag) uint64 {
	t.Helper()
	encodedLength := func(value any) uint64 {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return uint64(len(encoded))
	}
	switch value.Kind() {
	case reflect.Struct:
		size := uint64(2)
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			key := field.Tag.Get("json")
			if key == "" || strings.Contains(key, ",") {
				t.Fatal("wire field lacks an exact JSON key")
			}
			size += encodedLength(key) + 1 + turnSizeMetadataOracle(t, field.Type, key, field.Tag)
			if i > 0 {
				size++
			}
		}
		return size
	case reflect.Slice:
		count, err := strconv.ParseUint(tag.Get("limit"), 10, 16)
		if err != nil || count == 0 {
			t.Fatal("wire collection has no finite positive limit")
		}
		return 2 + count*turnSizeMetadataOracle(t, value.Elem(), "", "") + count - 1
	case reflect.String:
		if payload := tag.Get("payload"); payload != "" {
			if payload != "request" && payload != "response" {
				t.Fatal("wire payload tag changed")
			}
			return 2
		}
		limit := 64
		switch name {
		case "media_type", "model_id":
			limit = 255
		case "model_version", "connection_id":
			limit = 128
		}
		if text := tag.Get("limit"); text != "" {
			parsed, err := strconv.Atoi(text)
			if err != nil || parsed < 0 || parsed > 255 {
				t.Fatal("metadata text limit changed")
			}
			limit = parsed
		}
		return encodedLength(strings.Repeat("\x00", limit))
	case reflect.Bool:
		return encodedLength(false)
	case reflect.Uint8:
		return encodedLength(uint8(math.MaxUint8))
	case reflect.Uint32:
		return encodedLength(uint32(math.MaxUint32))
	case reflect.Uint64:
		return encodedLength(uint64(math.MaxUint64))
	case reflect.Int, reflect.Int64:
		return encodedLength(int64(math.MinInt64))
	default:
		t.Fatalf("unsupported wire kind: %s", value.Kind())
		return 0
	}
}

func TestInvestigationTurnSizeIndependentMetadataAndBase64Proof(t *testing.T) {
	before := turnSizeCloneShape(investigationTurnEncodingShape)
	defer func() {
		if !reflect.DeepEqual(before, investigationTurnEncodingShape) {
			t.Error("estimation mutated the accepted wire shape")
		}
	}()
	var estimate func(uint64) (uint64, error) = EstimateInvestigationTurnPayloadBytes
	metadata := turnSizeMetadataOracle(t, reflect.TypeOf(investigationTurnWire{}), "", "")
	if metadata != turnSizeMetadataCeiling {
		t.Fatalf("independent metadata sum = %d, want %d", metadata, turnSizeMetadataCeiling)
	}
	got, err := investigationTurnMetadataBound(investigationTurnEncodingShape)
	if err != nil || got != metadata {
		t.Fatalf("metadata helper = (%d, %v), independent sum %d", got, err, metadata)
	}
	response := uint64(base64.StdEncoding.EncodedLen(turnSizeResponseLimit) + 4*(turnSizePartCount-1))
	if response != turnSizeResponseBase64Ceiling {
		t.Fatalf("response aggregate expansion = %d", response)
	}
	for _, size := range []uint64{1, 2, 3, 4, 1024, 65536, 1 << 20, turnSizeRequestLimit} {
		got, err := estimate(size)
		want := metadata + uint64(base64.StdEncoding.EncodedLen(int(size))) + response
		if err != nil || got != want {
			t.Fatalf("size %d: bound = (%d, %v), want %d", size, got, err, want)
		}
	}
	// Artifact metadata validity and actual framing remain separate controller checks.
	artifactMetadata := uint64(2 + 16*(32+3) + 15 + 11*(2+6*128) + (2 + 31 + 32*(2+6*64)) + 2 + 3*20)
	if artifactMetadata != 21494 || artifactMetadata > 32<<10 {
		t.Fatal("fixed artifact metadata proof changed")
	}
	envelope := uint64(base64.StdEncoding.EncodedLen(turnSizeArtifactPayloadLimit)) + 32<<10
	if envelope != 22402392 || envelope >= 22<<20 {
		t.Fatal("16 MiB raw payload no longer implies 22 MiB encoded artifact fit")
	}
}

func TestInvestigationTurnSizeUsefulAdmissionMonotonicityAndOverflow(t *testing.T) {
	for _, size := range []uint64{0, turnSizeRequestLimit + 1, math.MaxUint64 - 2, math.MaxUint64 - 1, math.MaxUint64} {
		if bound, err := EstimateInvestigationTurnPayloadBytes(size); err == nil {
			t.Fatalf("invalid request length %d returned bound %d without error", size, bound)
		}
	}
	for _, size := range []uint64{1, 1024, 65536, 1 << 20} {
		bound, err := EstimateInvestigationTurnPayloadBytes(size)
		if err != nil || bound > turnSizeArtifactPayloadLimit {
			t.Fatalf("useful small request %d refused: (%d, %v)", size, bound, err)
		}
	}
	oversized, err := EstimateInvestigationTurnPayloadBytes(turnSizeRequestLimit)
	if err != nil || oversized != 23311174 || oversized <= turnSizeArtifactPayloadLimit {
		t.Fatalf("valid maximum request must return an inadmissible bound, not an error: (%d, %v)", oversized, err)
	}
	base := uint64(turnSizeMetadataCeiling + turnSizeResponseBase64Ceiling)
	lastAdmitted := (uint64(turnSizeArtifactPayloadLimit) - base) / 4 * 3
	for _, start := range []uint64{1, 1020, lastAdmitted - 6, turnSizeRequestLimit - 12} {
		previous := uint64(0)
		for size := start; size <= start+12 && size <= turnSizeRequestLimit; size++ {
			bound, err := EstimateInvestigationTurnPayloadBytes(size)
			want := base + uint64(base64.StdEncoding.EncodedLen(int(size)))
			if err != nil || bound != want || bound < previous {
				t.Fatalf("base64 staircase at %d = (%d, %v), previous %d, want %d", size, bound, err, previous, want)
			}
			if (bound <= turnSizeArtifactPayloadLimit) != (size <= lastAdmitted) {
				t.Fatalf("admission boundary mismatch at %d", size)
			}
			previous = bound
		}
	}
}

func turnSizeCloneShape(shape *investigationTurnShape) *investigationTurnShape {
	if shape == nil {
		return nil
	}
	copy := *shape
	if shape.fields != nil {
		copy.fields = make([]investigationTurnField, len(shape.fields))
		for i, field := range shape.fields {
			copy.fields[i] = investigationTurnField{prefix: field.prefix, shape: turnSizeCloneShape(field.shape)}
		}
	}
	copy.element = turnSizeCloneShape(shape.element)
	return &copy
}

func turnSizeField(t *testing.T, shape *investigationTurnShape, path ...string) *investigationTurnShape {
	t.Helper()
	for _, key := range path {
		if key == "[]" {
			if shape.element == nil {
				t.Fatal("fixture has no collection element")
			}
			shape = shape.element
			continue
		}
		var next *investigationTurnShape
		for _, field := range shape.fields {
			if field.prefix == `"`+key+`":` {
				next = field.shape
				break
			}
		}
		if next == nil {
			t.Fatalf("fixture field %q missing", key)
		}
		shape = next
	}
	return shape
}

func TestInvestigationTurnSizeShapeFailsClosed(t *testing.T) {
	baseline := turnSizeCloneShape(investigationTurnEncodingShape)
	defer func() {
		if !reflect.DeepEqual(baseline, investigationTurnEncodingShape) {
			t.Error("estimator mutated the accepted global shape")
		}
	}()
	if _, err := investigationTurnMetadataBound(nil); err == nil {
		t.Fatal("nil shape admitted")
	}
	request := func(shape *investigationTurnShape) *investigationTurnShape {
		return turnSizeField(t, shape, "request", "payload_b64")
	}
	parts := func(shape *investigationTurnShape) *investigationTurnShape {
		return turnSizeField(t, shape, "dispatch", "response", "parts")
	}
	response := func(shape *investigationTurnShape) *investigationTurnShape {
		return turnSizeField(t, shape, "dispatch", "response", "parts", "[]", "payload_b64")
	}
	for _, test := range []struct {
		name   string
		mutate func(*investigationTurnShape)
	}{
		{"missing request", func(s *investigationTurnShape) { request(s).payload = "" }},
		{"missing response", func(s *investigationTurnShape) { response(s).payload = "" }},
		{"unknown payload", func(s *investigationTurnShape) { response(s).payload = "future" }},
		{"request ceiling", func(s *investigationTurnShape) { request(s).limit++ }},
		{"response ceiling", func(s *investigationTurnShape) { response(s).limit++ }},
		{"smaller request ceiling", func(s *investigationTurnShape) { request(s).limit-- }},
		{"smaller response ceiling", func(s *investigationTurnShape) { response(s).limit-- }},
		{"missing parts cap", func(s *investigationTurnShape) { parts(s).limit = 0 }},
		{"negative parts cap", func(s *investigationTurnShape) { parts(s).limit = -1 }},
		{"larger parts cap", func(s *investigationTurnShape) { parts(s).limit++ }},
		{"smaller parts cap", func(s *investigationTurnShape) { parts(s).limit-- }},
		{"nil element", func(s *investigationTurnShape) { parts(s).element = nil }},
		{"nil field", func(s *investigationTurnShape) { s.fields[0].shape = nil }},
		{"cycle", func(s *investigationTurnShape) { s.fields[0].shape = s }},
		{"duplicate request object", func(s *investigationTurnShape) {
			s.fields = append(s.fields, investigationTurnField{prefix: `"request":`, shape: turnSizeField(t, s, "request")})
		}},
		{"duplicate response part payload", func(s *investigationTurnShape) {
			part := parts(s).element
			part.fields = append(part.fields, investigationTurnField{prefix: `"payload_b64":`, shape: response(s)})
		}},
		{"moved request", func(s *investigationTurnShape) {
			payload := *request(s)
			request(s).payload = ""
			s.fields = append(s.fields, investigationTurnField{prefix: `"payload_b64":`, shape: &payload})
		}},
		{"moved response", func(s *investigationTurnShape) {
			payload := *response(s)
			response(s).payload = ""
			turnSizeField(t, s, "dispatch", "response").fields = append(turnSizeField(t, s, "dispatch", "response").fields, investigationTurnField{prefix: `"payload_b64":`, shape: &payload})
		}},
		{"renamed request path", func(s *investigationTurnShape) {
			for i := range s.fields {
				if s.fields[i].prefix == `"request":` {
					s.fields[i].prefix = `"renamed":`
				}
			}
		}},
		{"renamed response parts path", func(s *investigationTurnShape) {
			object := turnSizeField(t, s, "dispatch", "response")
			for i := range object.fields {
				if object.fields[i].prefix == `"parts":` {
					object.fields[i].prefix = `"renamed":`
				}
			}
		}},
		{"swapped payload roles", func(s *investigationTurnShape) {
			request(s).payload, response(s).payload = "response", "request"
		}},
		{"extra nested payload", func(s *investigationTurnShape) {
			s.fields = append(s.fields, investigationTurnField{prefix: `"extra":`, shape: turnSizeCloneShape(turnSizeField(t, s, "request"))})
		}},
		{"request multiplicity", func(s *investigationTurnShape) {
			object := turnSizeField(t, s, "request")
			copy := *object
			*object = investigationTurnShape{kind: reflect.Slice, limit: 2, element: &copy}
		}},
		{"response multiplicity", func(s *investigationTurnShape) {
			part := parts(s).element
			parts(s).element = &investigationTurnShape{kind: reflect.Slice, limit: 2, element: part}
		}},
		{"payload on object", func(s *investigationTurnShape) { turnSizeField(t, s, "request").payload = "request" }},
		{"unbounded metadata collection", func(s *investigationTurnShape) { turnSizeField(t, s, "ranking", "ranked_routes").limit = 0 }},
		{"negative metadata text", func(s *investigationTurnShape) { turnSizeField(t, s, "identity").limit = -1 }},
		{"uint8 width mismatch", func(s *investigationTurnShape) { turnSizeField(t, s, "ordinal").bits = 64 }},
		{"uint32 width mismatch", func(s *investigationTurnShape) { turnSizeField(t, s, "declared_input_tokens").bits = 64 }},
		{"uint64 width mismatch", func(s *investigationTurnShape) { turnSizeField(t, s, "actual_cost_micro_usd").bits = 32 }},
		{"int64 width mismatch", func(s *investigationTurnShape) { turnSizeField(t, s, "deadline_milliseconds").bits = 32 }},
		{"depth", func(s *investigationTurnShape) {
			child := &investigationTurnShape{kind: reflect.Bool}
			for i := 0; i < 17; i++ {
				child = &investigationTurnShape{kind: reflect.Struct, fields: []investigationTurnField{{prefix: `"nested":`, shape: child}}}
			}
			s.fields = append(s.fields, investigationTurnField{prefix: `"deep":`, shape: child})
		}},
		{"checked arithmetic", func(s *investigationTurnShape) {
			maximumInt := int(^uint(0) >> 1)
			child := &investigationTurnShape{kind: reflect.String, limit: maximumInt}
			for i := 0; i < 2; i++ {
				child = &investigationTurnShape{kind: reflect.Slice, limit: maximumInt, element: child}
			}
			s.fields = append(s.fields, investigationTurnField{prefix: `"overflow":`, shape: child})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			shape := turnSizeCloneShape(investigationTurnEncodingShape)
			test.mutate(shape)
			if bound, err := investigationTurnMetadataBound(shape); err == nil {
				t.Fatalf("malformed shape returned bound %d without error", bound)
			}
		})
	}
	for _, kind := range []reflect.Kind{reflect.Invalid, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Uint, reflect.Uint16, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.UnsafePointer} {
		t.Run(kind.String(), func(t *testing.T) {
			shape := turnSizeCloneShape(investigationTurnEncodingShape)
			turnSizeField(t, shape, "actual_cost_micro_usd").kind = kind
			if _, err := investigationTurnMetadataBound(shape); err == nil {
				t.Fatal("unsupported kind admitted")
			}
		})
	}
	for _, field := range []string{"actual_cost_micro_usd", "declared_input_tokens", "ordinal", "deadline_milliseconds", "schema_version"} {
		for _, bits := range []int{-1, 0, 7, 33, 65} {
			t.Run(fmt.Sprintf("%s/bits-%d", field, bits), func(t *testing.T) {
				shape := turnSizeCloneShape(investigationTurnEncodingShape)
				turnSizeField(t, shape, field).bits = bits
				if _, err := investigationTurnMetadataBound(shape); err == nil {
					t.Fatal("malformed scalar width admitted")
				}
			})
		}
	}
	shape := turnSizeCloneShape(investigationTurnEncodingShape)
	shape.fields = append(shape.fields, investigationTurnField{prefix: `"extra":`, shape: &investigationTurnShape{kind: reflect.String, limit: 255}})
	bound, err := investigationTurnMetadataBound(shape)
	if err != nil || bound != uint64(turnSizeMetadataCeiling+len(`"extra":`)+1+2+6*255) {
		t.Fatalf("new bounded ordinary metadata not conservatively counted: (%d, %v)", bound, err)
	}
}

func TestInvestigationTurnSizeEstimatorDoesNotMaterializePayloads(t *testing.T) {
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bound, err := EstimateInvestigationTurnPayloadBytes(turnSizeRequestLimit)
			if err != nil || bound <= turnSizeArtifactPayloadLimit {
				b.Fatal("maximum-length estimate changed")
			}
		}
	})
	if result.N == 0 {
		t.Fatal("estimator allocation measurement did not complete")
	}
	if result.AllocedBytesPerOp() > 64<<10 {
		t.Fatalf("length-only estimator allocates %d bytes/op; multi-megabyte witness payloads belong only in tests", result.AllocedBytesPerOp())
	}
}

func turnSizeMediaType(base string) string {
	prefix, suffix := base+`;note="<>&\"\\`, `"`
	return prefix + strings.Repeat("x", 255-len(prefix)-len(suffix)) + suffix
}

type turnSizeDispatcher struct {
	t               *testing.T
	adapter         string
	ledger          audit.Ledger
	scope           audit.ReviewScope
	calls           int
	requestIdentity string
	responseBytes   int
	responseParts   int
	escapedMedia    bool
	maximumUsage    bool
}

func (d *turnSizeDispatcher) AdapterID() string             { return d.adapter }
func (d *turnSizeDispatcher) ConfigurationIdentity() string { return strings.Repeat("d", 64) }
func (d *turnSizeDispatcher) DispatchRoute(ctx context.Context, request RouteDispatchRequest) RouteDispatchResult {
	d.calls++
	d.requestIdentity = request.Request().Identity()
	if request.Validate() != nil {
		d.t.Fatal("fake model received invalid dispatch request")
	}
	events, err := d.ledger.Read(ctx, d.scope, 0, 100)
	if err != nil {
		d.t.Fatal(err)
	}
	claimed := false
	for _, event := range events {
		if event.Kind() == audit.EventRouteAttemptClaimed && event.SubjectIdentity() == request.Authorization().Identity() {
			claimed = true
		}
	}
	if !claimed {
		d.t.Fatal("fake model call preceded real owner claim")
	}
	media := "text/plain"
	if d.escapedMedia {
		media = turnSizeMediaType(media)
	}
	parts := make([]provider.ResponsePart, d.responseParts)
	for i := range parts {
		size := d.responseBytes / len(parts)
		if i < d.responseBytes%len(parts) {
			size++
		}
		payload := make([]byte, size)
		pattern := []byte{'<', '>', '&', '"', '\\', '\n', '\t', 0}
		for j := 0; j < len(payload); j++ {
			payload[j] = pattern[j%len(pattern)]
		}
		unicodePrefix := []byte("é\u2028\u2029😀")
		if len(payload) >= len(unicodePrefix) {
			copy(payload, unicodePrefix)
		}
		parts[i], err = provider.NewResponsePart(provider.ResponsePartAssistantText, media, payload)
		if err != nil {
			d.t.Fatal(err)
		}
	}
	input, output, cached := uint64(1), uint64(1), uint64(0)
	if d.maximumUsage {
		input, output, cached = 1<<30, 1<<30, 1<<30
	}
	usage, err := provider.NewRouteTokenUsage(input, output, cached)
	if err != nil {
		d.t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, parts, usage)
	if err != nil {
		d.t.Fatal(err)
	}
	result, err := NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		d.t.Fatal(err)
	}
	return result
}

func turnSizeOwner(t *testing.T, routeCount, rejected int, maximumMetadata bool, dispatcher *turnSizeDispatcher) *InvestigationRouteOwner {
	t.Helper()
	options, _, clock, ledger := investigationOwnerOptionsFixture(t, "", 1<<62, 1)
	manifest := []byte("turn size route evidence")
	if maximumMetadata {
		manifest = bytes.Repeat([]byte("m"), 1<<20)
	}
	digest := sha256.Sum256(manifest)
	adapter := strings.Repeat("a", 64)
	revision := uint64(21)
	if maximumMetadata {
		revision = math.MaxUint64
	}
	routes := make([]ObservedRouteCandidate, routeCount)
	observations := make([]provider.RoutePerformanceObservation, routeCount)
	preferences := make([]provider.RouteReference, routeCount)
	for i := range routes {
		providerID, connection, model, version := "fixture", "fixture", fmt.Sprintf("model-%02d", i), "v1"
		if maximumMetadata {
			providerID = strings.Repeat("p", 64)
			connection = strings.Repeat("c", 128)
			model = strings.Repeat("m", 252) + fmt.Sprintf("%03d", i)
			version = strings.Repeat("v", 128)
		}
		reference, err := provider.NewRouteReference(provider.ProviderZoneLocal, providerID, adapter, connection, model, version)
		if err != nil {
			t.Fatal(err)
		}
		capabilities, err := provider.NewModelCapabilities(1<<30, 1<<30, []provider.ModelFeature{provider.ModelFeatureStructuredOutput, provider.ModelFeatureNativeTools, provider.ModelFeatureVision})
		if err != nil {
			t.Fatal(err)
		}
		capability, err := provider.NewRouteCapabilityDeclaration(reference, capabilities)
		if err != nil {
			t.Fatal(err)
		}
		price := uint64(1000000)
		if maximumMetadata {
			price = 1 << 30
		}
		pricing, err := provider.NewRoutePricing(price, price)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := provider.NewRouteCandidateDeclaration(capability, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier4)
		if err != nil {
			t.Fatal(err)
		}
		record, err := provider.NewRouteRegistryRecord(revision, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := ResolveRouteRegistryRecord(context.Background(), record.Identity(), &routeRegistryReaderStub{record: record}, &routeEvidenceManifestReaderStub{content: manifest})
		if err != nil {
			t.Fatal(err)
		}
		health := provider.RouteHealthHealthy
		if i >= routeCount-rejected {
			health = provider.RouteHealthUnhealthy
		}
		state, err := provider.NewRouteOperationalState(record.Identity(), revision, health, provider.RouteQuotaAvailable)
		if err != nil {
			t.Fatal(err)
		}
		routes[i], err = NewObservedRouteCandidate(resolved, state)
		if err != nil {
			t.Fatal(err)
		}
		observations[i], err = provider.NewKnownRoutePerformanceObservation(record.Identity(), revision, 86400000, math.MaxUint32)
		if err != nil {
			t.Fatal(err)
		}
		preferences[i] = reference
	}
	ranking, err := NewPinnedRouteRankingPolicy(preferences[0], preferences[1:])
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewInvestigationRoutePlan(revision, routes, ranking, revision, observations)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.t, dispatcher.adapter, dispatcher.ledger, dispatcher.scope = t, adapter, ledger, options.Scope
	catalog, err := NewRouteDispatcherCatalog([]RouteDispatcher{dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	options.Generation, options.Verification, options.Catalog = plan, plan, catalog
	clock.at = time.UnixMilli(253402300799999 - int64((15*time.Minute)/time.Millisecond))
	options.Deadline = clock.at.Add(15 * time.Minute)
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func TestInvestigationTurnSizeBoundsActualOwnerEncodings(t *testing.T) {
	for _, test := range []struct {
		name            string
		requestBytes    int
		responseBytes   int
		parts           int
		routes          int
		rejected        int
		maximumMetadata bool
	}{
		{"opaque single byte", 1, 1, 1, 1, 0, false},
		{"opaque remainder two", 2, 11, 4, 4, 0, false},
		{"escaped fragments and rejections", 65536, 64, 64, 64, 31, true},
		{"maximum single part", 3, turnSizePartLimit, 1, 1, 0, false},
		{"maximum aggregate four parts", 2, turnSizeResponseLimit, 4, 1, 0, false},
		{"maximum aggregate sixty four parts", 1 << 20, turnSizeResponseLimit, 64, 64, 0, true},
		{"maximum rejection count", 1, 1, 1, 64, 63, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := make([]byte, test.requestBytes)
			pattern := []byte{0xff, 0, '"', '\\', '<', '>', '&', 0xc3, 0xa9}
			for i := range payload {
				payload[i] = pattern[i%len(pattern)]
			}
			request, err := provider.NewRequest(provider.CapabilityReviewV1, turnSizeMediaType("application/json"), payload)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := &turnSizeDispatcher{responseBytes: test.responseBytes, responseParts: test.parts, escapedMedia: true, maximumUsage: test.maximumMetadata}
			owner := turnSizeOwner(t, test.routes, test.rejected, test.maximumMetadata, dispatcher)
			before := owner.State()
			bound, err := EstimateInvestigationTurnPayloadBytes(uint64(len(payload)))
			if err != nil || bound > turnSizeArtifactPayloadLimit || dispatcher.calls != 0 || owner.State() != before {
				t.Fatalf("pre-dispatch estimate failed or changed owner: (%d, %v)", bound, err)
			}
			turn, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, request)
			if err != nil || dispatcher.calls != 1 || dispatcher.requestIdentity != request.Identity() || turn.Validate() != nil {
				t.Fatalf("actual owner dispatch failed: %v", err)
			}
			if !bytes.Equal(turn.request.Payload(), payload) || turn.RequestIdentity() != request.Identity() {
				t.Fatal("bound was not tied to the same opaque dispatched request")
			}
			if len(turn.ranking.RankedRoutes()) != test.routes-test.rejected || len(turn.Selection().CandidateScores()) != test.routes-test.rejected || len(turn.Selection().Rejections()) != test.rejected {
				t.Fatal("fixture did not exercise expected ranking and rejection counts")
			}
			if len(request.MediaType()) != 255 || !turn.ranking.RankedRoutes()[0].IsPinned() {
				t.Fatal("maximum request metadata or pinned ranking witness missing")
			}
			if test.maximumMetadata {
				for _, ranked := range turn.ranking.RankedRoutes() {
					resolved := ranked.Route().ResolvedRecord()
					registry := resolved.RouteRegistryRecord()
					candidate := registry.RouteCandidateDeclaration()
					reference := candidate.RouteCapabilityDeclaration().RouteReference()
					if len(reference.ProviderID()) != 64 || len(reference.AdapterID()) != 64 || len(reference.ConnectionID()) != 128 || len(reference.ModelID()) != 255 || len(reference.ModelVersion()) != 128 || registry.RegistryRevision() != math.MaxUint64 || resolved.EvidenceManifestSizeBytes() != 1<<20 {
						t.Fatal("maximum registry metadata witness missing")
					}
					if len(candidate.RouteCapabilityDeclaration().ModelCapabilities().SupportedFeatures()) != 3 || ranked.Performance().ObservationRevision() != math.MaxUint64 || ranked.Performance().SampleCount() != math.MaxUint32 || ranked.Performance().P95LatencyMilliseconds() != 86400000 || ranked.Route().OperationalState().ObservationRevision() != math.MaxUint64 {
						t.Fatal("maximum feature/performance/operational metadata witness missing")
					}
				}
			}
			response := turn.Dispatch().Response()
			if test.maximumMetadata && (response.Usage().InputTokens() != 1<<30 || response.Usage().OutputTokens() != 1<<30 || response.Usage().CachedInputTokens() != 1<<30) {
				t.Fatal("maximum scalar usage witness missing")
			}
			total, encodedParts := 0, 0
			for _, part := range response.Parts() {
				total += part.SizeBytes()
				encodedParts += base64.StdEncoding.EncodedLen(part.SizeBytes())
				if part.SizeBytes() > turnSizePartLimit || len(part.MediaType()) != 255 {
					t.Fatal("part limit or escaped metadata witness missing")
				}
			}
			if response.PartCount() != test.parts || total != test.responseBytes || encodedParts > turnSizeResponseBase64Ceiling {
				t.Fatal("actual normalized response does not match aggregate/fragmentation witness")
			}
			encoded, err := EncodeInvestigationTurnRecord(turn)
			if err != nil || uint64(len(encoded)) > bound || len(encoded) > turnSizeArtifactPayloadLimit {
				t.Fatalf("actual owner turn encoding %d exceeds bound %d: %v", len(encoded), bound, err)
			}
			if !bytes.Contains(encoded, []byte(`\u003c`)) || !bytes.Contains(encoded, []byte(`\u0026`)) || !bytes.Contains(encoded, []byte(`\\`)) {
				t.Fatal("canonical encoding did not exercise JSON metadata escaping")
			}
			actualMetadata := len(encoded) - base64.StdEncoding.EncodedLen(len(payload)) - encodedParts
			if actualMetadata > turnSizeMetadataCeiling {
				t.Fatalf("actual metadata %d exceeds conservative bound", actualMetadata)
			}
		})
	}
}

func TestInvestigationTurnSizeLocalAdmissionRefusesBeforeModelEffect(t *testing.T) {
	dispatcher := &turnSizeDispatcher{responseBytes: turnSizeResponseLimit, responseParts: 64}
	owner := turnSizeOwner(t, 1, 0, false, dispatcher)
	payload := bytes.Repeat([]byte{0xff}, turnSizeRequestLimit)
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/octet-stream", payload)
	if err != nil {
		t.Fatal(err)
	}
	before := owner.State()
	bound, err := EstimateInvestigationTurnPayloadBytes(uint64(len(payload)))
	if err != nil || bound <= turnSizeArtifactPayloadLimit {
		t.Fatalf("maximum request lacks pre-dispatch refusal bound: (%d, %v)", bound, err)
	}
	// This branch is test-local orchestration, not an implemented controller gate.
	if err == nil && bound <= turnSizeArtifactPayloadLimit {
		_, _ = owner.Dispatch(context.Background(), InvestigationGenerationTurn, request)
	}
	events, readErr := dispatcher.ledger.Read(context.Background(), dispatcher.scope, 0, 100)
	if readErr != nil || len(events) != 0 || dispatcher.calls != 0 || owner.State() != before {
		t.Fatal("size refusal selected, claimed, dispatched, or spent")
	}
	if !bytes.Equal(request.Payload(), payload) {
		t.Fatal("admission measured bytes from a different request")
	}
}
