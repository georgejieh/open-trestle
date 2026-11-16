// Package modelcatalog stages metadata availability separately from runtime authority.
package modelcatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
)

const (
	// MaxResponseBytes bounds one live model-list HTTP body. It admits a fetch
	// only and binds no recorded catalog, digest or identity. OpenRouter's public
	// list measured 829,400 bytes, so 4 MiB leaves room to grow.
	MaxResponseBytes = 4 << 20
	maxFileBytes     = 8 << 20
	maxSources       = 32
	maxModels        = 10000
)

var (
	ErrInvalid     = errors.New("invalid model catalog document")
	ErrConflict    = errors.New("model catalog digest conflict")
	ErrProtected   = errors.New("model catalog protected path unavailable or unstable")
	ErrPersistence = errors.New("model catalog persistence failed")
	// ErrDurability means replacement happened but its directory sync failed.
	ErrDurability = errors.New("model catalog replaced; directory durability unconfirmed")
)

type Source struct {
	ID                    string `json:"id"`
	Kind                  string `json:"kind"`
	URL                   string `json:"url"`
	CredentialEnvironment string `json:"credential_environment,omitempty"`
}

func (s *Source) UnmarshalJSON(data []byte) error {
	type sourceFields Source
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return ErrInvalid
	}
	for name := range fields {
		if strings.EqualFold(name, "credential_environment") && name != "credential_environment" {
			return ErrInvalid
		}
	}
	if raw, present := fields["credential_environment"]; present {
		var reference string
		if json.Unmarshal(raw, &reference) != nil || !validCredentialReference(reference) {
			return ErrInvalid
		}
	}
	var value sourceFields
	if decode(data, &value, true) != nil {
		return ErrInvalid
	}
	*s = Source(value)
	return nil
}

type Manifest struct {
	SchemaVersion int      `json:"schema_version"`
	Sources       []Source `json:"sources"`
}
type Model struct {
	Selector string          `json:"selector"`
	Metadata json.RawMessage `json:"metadata"`
}

// MarshalJSON escapes only quotation marks, reverse solidi and control
// characters in the selector, so a stored selector is never longer than its
// encoding in the model list it came from. Metadata is compacted unchanged.
func (m Model) MarshalJSON() ([]byte, error) {
	if !utf8.ValidString(m.Selector) {
		return nil, ErrInvalid
	}
	encoded := append(make([]byte, 0, len(m.Selector)+len(m.Metadata)+32), `{"selector":"`...)
	for i := 0; i < len(m.Selector); i++ {
		switch c := m.Selector[i]; {
		case c == '"' || c == '\\':
			encoded = append(encoded, '\\', c)
		case c < 0x20:
			encoded = append(encoded, fmt.Sprintf(`\u%04x`, c)...)
		default:
			encoded = append(encoded, c)
		}
	}
	encoded = append(encoded, `","metadata":`...)
	if m.Metadata == nil {
		return append(encoded, `null}`...), nil
	}
	var metadata bytes.Buffer
	if json.Compact(&metadata, m.Metadata) != nil {
		return nil, ErrInvalid
	}
	return append(append(encoded, metadata.Bytes()...), '}'), nil
}

type Snapshot struct {
	Source         Source  `json:"source"`
	RetrievedAt    string  `json:"retrieved_at,omitempty"`
	ResponseDigest string  `json:"response_digest,omitempty"`
	Models         []Model `json:"models"`
}
type Failure struct {
	SourceID string `json:"source_id"`
	Code     string `json:"code"`
}
type Catalog struct {
	SchemaVersion int        `json:"schema_version"`
	Sources       []Snapshot `json:"sources"`
	Failures      []Failure  `json:"failures"`
}
type Proposal struct {
	SchemaVersion  int     `json:"schema_version"`
	ManifestDigest string  `json:"manifest_digest"`
	CurrentDigest  string  `json:"current_digest"`
	Catalog        Catalog `json:"catalog"`
}
type Entry struct {
	SourceID string          `json:"source_id"`
	Selector string          `json:"selector"`
	Metadata json.RawMessage `json:"metadata"`
}
type Change struct {
	Before Entry `json:"before"`
	After  Entry `json:"after"`
}
type Diff struct {
	Added   []Entry  `json:"added"`
	Removed []Entry  `json:"removed"`
	Changed []Change `json:"changed"`
}
type Review struct {
	ProposalDigest string    `json:"proposal_digest"`
	CurrentDigest  string    `json:"current_digest"`
	Diff           Diff      `json:"diff"`
	Failures       []Failure `json:"failures"`
}

func Digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }
func digestValid(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
func selectorValid(value string) bool {
	if value == "" || len(value) > 1024 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func sourceIDValid(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
func decode(data []byte, target any, strict bool) error {
	if len(data) == 0 || len(data) > maxFileBytes || !utf8.Valid(data) {
		return ErrInvalid
	}
	if err := validJSONUnicodeEscapes(data); err != nil {
		return ErrInvalid
	}
	if err := uniqueJSON(data); err != nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validJSONUnicodeEscapes(data []byte) error {
	codeUnit := func(offset int) (uint64, error) {
		if offset+4 > len(data) {
			return 0, ErrInvalid
		}
		return strconv.ParseUint(string(data[offset:offset+4]), 16, 16)
	}
	quoted := false
	for index := 0; index < len(data); index++ {
		if data[index] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || data[index] != '\\' {
			continue
		}
		if index+1 >= len(data) {
			return ErrInvalid
		}
		if data[index+1] != 'u' {
			index++
			continue
		}
		unit, err := codeUnit(index + 2)
		if err != nil {
			return ErrInvalid
		}
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+8 > len(data) || data[index+6] != '\\' || data[index+7] != 'u' {
				return ErrInvalid
			}
			low, err := codeUnit(index + 8)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return ErrInvalid
			}
			index += 11
		case unit >= 0xdc00 && unit <= 0xdfff:
			return ErrInvalid
		default:
			index += 5
		}
	}
	return nil
}

// maxDocumentDepth bounds the nesting of every decoded document.
const maxDocumentDepth = 64

// storedModelDepth is the depth of a model's metadata object in a stored
// proposal, the deepest document that holds it: proposal, catalog, sources,
// snapshot, models, model, metadata. In a model list the model object is at
// depth 2, so a stored model is four levels deeper than its list.
const storedModelDepth = 6

func uniqueJSON(data []byte) error {
	return uniqueJSONWithin(data, maxDocumentDepth)
}

// uniqueJSONWithin refuses duplicate object keys and any value nested deeper
// than limit, counting the top-level value as depth 0.
func uniqueJSONWithin(data []byte, limit int) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > limit {
			return ErrInvalid
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return ErrInvalid
				}
				keys[name] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrInvalid
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
func parseModels(kind string, data []byte) ([]Model, error) {
	if len(data) > MaxResponseBytes {
		return nil, ErrInvalid
	}
	var envelope map[string]json.RawMessage
	if decode(data, &envelope, false) != nil {
		return nil, ErrInvalid
	}
	field, selector := "data", "id"
	if kind == "ollama_tags" {
		field, selector = "models", "name"
	} else if kind != "openai_models" {
		return nil, ErrInvalid
	}
	raw, ok := envelope[field]
	if !ok || len(raw) == 0 || raw[0] != '[' {
		return nil, ErrInvalid
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) > maxModels {
		return nil, ErrInvalid
	}
	models := make([]Model, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		var fields map[string]json.RawMessage
		var name string
		// A list the fetch accepts must still fit the depth bound once stored.
		if uniqueJSONWithin(row, maxDocumentDepth-storedModelDepth) != nil || json.Unmarshal(row, &fields) != nil || fields == nil || json.Unmarshal(fields[selector], &name) != nil || !selectorValid(name) || seen[name] {
			return nil, ErrInvalid
		}
		seen[name] = true
		metadata, err := modelMetadata(row, selector)
		if err != nil {
			return nil, ErrInvalid
		}
		models = append(models, Model{Selector: name, Metadata: metadata})
	}
	sort.Slice(models, func(i, j int) bool { return models[i].Selector < models[j].Selector })
	return models, nil
}

// modelMetadata returns the rest of one model object: its exact members in
// list order, compacted, without the selector member that Model already
// stores. It never re-encodes a key or value, so it is never longer than the
// object in the list.
func modelMetadata(row json.RawMessage, selector string) (json.RawMessage, error) {
	var compact bytes.Buffer
	if json.Compact(&compact, row) != nil {
		return nil, ErrInvalid
	}
	data := compact.Bytes()
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	metadata := []byte{'{'}
	for decoder.More() {
		start := decoder.InputOffset()
		if data[start] == ',' {
			start++
		}
		key, err := decoder.Token()
		name, ok := key.(string)
		var value json.RawMessage
		if err != nil || !ok || decoder.Decode(&value) != nil {
			return nil, ErrInvalid
		}
		if name == selector {
			continue
		}
		if len(metadata) > 1 {
			metadata = append(metadata, ',')
		}
		metadata = append(metadata, data[start:decoder.InputOffset()]...)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalid
	}
	return append(metadata, '}'), nil
}

// encodeDocument writes a catalog or proposal as compact JSON without HTML
// escaping, plus a trailing newline. With modelMetadata and Model.MarshalJSON
// each stored model is at most 20 bytes longer than its object in the model
// list, so one list within MaxResponseBytes, at most maxModels models, always
// fits maxFileBytes. Earlier catalogs and proposals were indented; they still
// decode.
func encodeDocument(value any) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil, ErrInvalid
	}
	return encoded.Bytes(), nil
}

func validateManifest(manifest Manifest, allowRemote bool) error {
	if (manifest.SchemaVersion != 1 && manifest.SchemaVersion != 2) || manifest.Sources == nil || len(manifest.Sources) == 0 || len(manifest.Sources) > maxSources {
		return ErrInvalid
	}
	seen := map[string]bool{}
	credentialOrigins := map[string]string{}
	for _, source := range manifest.Sources {
		if seen[source.ID] || validateSource(source, allowRemote) != nil || manifest.SchemaVersion == 1 && source.CredentialEnvironment != "" {
			return ErrInvalid
		}
		if source.CredentialEnvironment != "" {
			endpoint, _ := url.Parse(source.URL)
			origin := endpoint.Scheme + "://" + endpoint.Host
			if prior, found := credentialOrigins[source.CredentialEnvironment]; found && prior != origin {
				return ErrInvalid
			}
			credentialOrigins[source.CredentialEnvironment] = origin
		}
		seen[source.ID] = true
	}
	return nil
}
func validateCatalog(catalog Catalog) error {
	if (catalog.SchemaVersion != 1 && catalog.SchemaVersion != 2) || catalog.Sources == nil || catalog.Failures == nil || len(catalog.Sources) > maxSources {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, snapshot := range catalog.Sources {
		if validateSource(snapshot.Source, true) != nil || catalog.SchemaVersion == 1 && snapshot.Source.CredentialEnvironment != "" || seen[snapshot.Source.ID] || snapshot.Models == nil || len(snapshot.Models) > maxModels {
			return ErrInvalid
		}
		seen[snapshot.Source.ID] = true
		if snapshot.RetrievedAt == "" {
			if snapshot.ResponseDigest != "" || len(snapshot.Models) != 0 {
				return ErrInvalid
			}
		} else {
			stamp, err := time.Parse(time.RFC3339Nano, snapshot.RetrievedAt)
			if err != nil || stamp.IsZero() || !digestValid(snapshot.ResponseDigest) {
				return ErrInvalid
			}
		}
		names := map[string]bool{}
		for _, model := range snapshot.Models {
			if !selectorValid(model.Selector) || names[model.Selector] {
				return ErrInvalid
			}
			names[model.Selector] = true
			selector := "id"
			if snapshot.Source.Kind == "ollama_tags" {
				selector = "name"
			}
			// Metadata stores the rest of the model object. Catalogs written
			// before that stored the whole object, so a selector member must
			// still name the model.
			var row map[string]json.RawMessage
			var name string
			if decode(model.Metadata, &row, false) != nil || row == nil {
				return ErrInvalid
			}
			if value, present := row[selector]; present && (json.Unmarshal(value, &name) != nil || name != model.Selector) {
				return ErrInvalid
			}
		}
	}
	failed := map[string]bool{}
	for _, failure := range catalog.Failures {
		if !seen[failure.SourceID] || failed[failure.SourceID] || failure.Code != "metadata_unavailable" {
			return ErrInvalid
		}
		failed[failure.SourceID] = true
	}
	for _, snapshot := range catalog.Sources {
		if snapshot.RetrievedAt == "" && !failed[snapshot.Source.ID] {
			return ErrInvalid
		}
	}
	return nil
}
func metadataEqual(a, b json.RawMessage) bool {
	var left, right any
	leftDecoder := json.NewDecoder(bytes.NewReader(a))
	leftDecoder.UseNumber()
	rightDecoder := json.NewDecoder(bytes.NewReader(b))
	rightDecoder.UseNumber()
	return leftDecoder.Decode(&left) == nil && rightDecoder.Decode(&right) == nil && reflect.DeepEqual(left, right)
}

func snapshotEqual(a, b Snapshot) bool {
	if a.Source != b.Source || a.RetrievedAt != b.RetrievedAt || a.ResponseDigest != b.ResponseDigest || len(a.Models) != len(b.Models) {
		return false
	}
	for i, model := range a.Models {
		if model.Selector != b.Models[i].Selector || !metadataEqual(model.Metadata, b.Models[i].Metadata) {
			return false
		}
	}
	return true
}

// modelMetadataEqual compares stored metadata without the selector member, which
// catalogs written before modelMetadata kept inside it.
func modelMetadataEqual(kind string, a, b json.RawMessage) bool {
	selector := "id"
	if kind == "ollama_tags" {
		selector = "name"
	}
	rest := func(metadata json.RawMessage) (map[string]any, bool) {
		var fields map[string]any
		decoder := json.NewDecoder(bytes.NewReader(metadata))
		decoder.UseNumber()
		if decoder.Decode(&fields) != nil {
			return nil, false
		}
		delete(fields, selector)
		return fields, true
	}
	left, leftOK := rest(a)
	right, rightOK := rest(b)
	return leftOK && rightOK && reflect.DeepEqual(left, right)
}

func catalogDiff(before, after Catalog) Diff {
	kinds := map[string]string{}
	flatten := func(c Catalog) map[string]Entry {
		entries := map[string]Entry{}
		for _, s := range c.Sources {
			kinds[s.Source.ID] = s.Source.Kind
			for _, m := range s.Models {
				entries[s.Source.ID+"\x00"+m.Selector] = Entry{s.Source.ID, m.Selector, m.Metadata}
			}
		}
		return entries
	}
	old, next := flatten(before), flatten(after)
	diff := Diff{Added: []Entry{}, Removed: []Entry{}, Changed: []Change{}}
	keys := make([]string, 0, len(old)+len(next))
	seen := map[string]bool{}
	for k := range old {
		seen[k] = true
		keys = append(keys, k)
	}
	for k := range next {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		a, aok := old[key]
		b, bok := next[key]
		switch {
		case !aok:
			diff.Added = append(diff.Added, b)
		case !bok:
			diff.Removed = append(diff.Removed, a)
		default:
			if !modelMetadataEqual(kinds[a.SourceID], a.Metadata, b.Metadata) {
				diff.Changed = append(diff.Changed, Change{a, b})
			}
		}
	}
	return diff
}

// Refresh writes a new review proposal, never the current catalog.
func Refresh(ctx context.Context, sourcesPath, currentPath, proposalPath string, allowRemote bool) (Review, error) {
	return RefreshWithCredentials(ctx, sourcesPath, currentPath, proposalPath, allowRemote, nil)
}

// CredentialResolver binds a reference to a deferred credential provider.
type CredentialResolver interface {
	ResolveOpenAICredentials(string) (openai.APIKeyProvider, error)
}

// RefreshWithCredentials reads referenced credentials only for validated metadata requests.
func RefreshWithCredentials(ctx context.Context, sourcesPath, currentPath, proposalPath string, allowRemote bool, resolver CredentialResolver) (Review, error) {
	if ctx == nil || ctx.Err() != nil {
		return Review{}, ErrInvalid
	}
	if distinctPaths(sourcesPath, currentPath, proposalPath) != nil {
		return Review{}, ErrProtected
	}
	authority, err := readProtected(sourcesPath, false)
	if err != nil {
		return Review{}, err
	}
	var manifest Manifest
	if decode(authority, &manifest, true) != nil || validateManifest(manifest, allowRemote) != nil {
		return Review{}, ErrInvalid
	}
	current, currentDigest, err := readCatalog(currentPath)
	if err != nil {
		return Review{}, err
	}
	previous := map[string]Snapshot{}
	for _, snapshot := range current.Sources {
		previous[snapshot.Source.ID] = snapshot
	}
	next := Catalog{SchemaVersion: manifest.SchemaVersion, Sources: []Snapshot{}, Failures: []Failure{}}
	for _, source := range manifest.Sources {
		if old, ok := previous[source.ID]; ok && old.Source != source {
			return Review{}, ErrInvalid
		}
	}
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for _, source := range manifest.Sources {
		snapshot, fetchErr := fetchWithCredentials(bounded, source, resolver)
		if fetchErr != nil {
			snapshot = Snapshot{Source: source, Models: []Model{}}
			if old, ok := previous[source.ID]; ok {
				snapshot = old
			}
			next.Failures = append(next.Failures, Failure{source.ID, "metadata_unavailable"})
		}
		next.Sources = append(next.Sources, snapshot)
	}
	if ctx.Err() != nil {
		return Review{}, ctx.Err()
	}
	sort.Slice(next.Sources, func(i, j int) bool { return next.Sources[i].Source.ID < next.Sources[j].Source.ID })
	sort.Slice(next.Failures, func(i, j int) bool { return next.Failures[i].SourceID < next.Failures[j].SourceID })
	if validateCatalog(next) != nil {
		return Review{}, ErrInvalid
	}
	again, err := readProtected(sourcesPath, false)
	if err != nil || !bytes.Equal(authority, again) {
		return Review{}, ErrConflict
	}
	proposal := Proposal{1, Digest(authority), currentDigest, next}
	encoded, err := encodeDocument(proposal)
	if err != nil {
		return Review{}, ErrInvalid
	}
	var serialized Proposal
	if decode(encoded, &serialized, true) != nil || validateCatalog(serialized.Catalog) != nil {
		return Review{}, ErrInvalid
	}
	if err = writeAtomic(ctx, proposalPath, encoded, "absent", func() error { return nil }); err != nil {
		return Review{}, err
	}
	return Review{Digest(encoded), currentDigest, catalogDiff(current, next), next.Failures}, nil
}

// Apply installs only the exact reviewed proposal against its exact base catalog.
func Apply(ctx context.Context, sourcesPath, currentPath, proposalPath, expectedProposal, expectedCurrent string) error {
	if ctx == nil || ctx.Err() != nil || !digestValid(expectedProposal) || (expectedCurrent != "absent" && !digestValid(expectedCurrent)) {
		return ErrInvalid
	}
	if distinctPaths(sourcesPath, currentPath, proposalPath) != nil {
		return ErrProtected
	}
	data, err := readProtected(proposalPath, false)
	if err != nil {
		return err
	}
	if Digest(data) != expectedProposal {
		return ErrConflict
	}
	var proposal Proposal
	if decode(data, &proposal, true) != nil || proposal.SchemaVersion != 1 || proposal.CurrentDigest != expectedCurrent || !digestValid(proposal.ManifestDigest) || validateCatalog(proposal.Catalog) != nil {
		return ErrInvalid
	}
	authority, err := readProtected(sourcesPath, false)
	if err != nil {
		return err
	}
	if Digest(authority) != proposal.ManifestDigest {
		return ErrConflict
	}
	var manifest Manifest
	if decode(authority, &manifest, true) != nil || validateManifest(manifest, true) != nil || len(manifest.Sources) != len(proposal.Catalog.Sources) {
		return ErrInvalid
	}
	sources := map[string]Source{}
	for _, s := range manifest.Sources {
		sources[s.ID] = s
	}
	for _, s := range proposal.Catalog.Sources {
		if sources[s.Source.ID] != s.Source {
			return ErrInvalid
		}
	}
	current, base, err := readCatalog(currentPath)
	if err != nil {
		return err
	}
	if base != expectedCurrent {
		return ErrConflict
	}
	old := map[string]Snapshot{}
	for _, s := range current.Sources {
		old[s.Source.ID] = s
	}
	failed := map[string]bool{}
	for _, f := range proposal.Catalog.Failures {
		failed[f.SourceID] = true
	}
	for _, s := range proposal.Catalog.Sources {
		previous, exists := old[s.Source.ID]
		if exists && previous.Source != s.Source {
			return ErrInvalid
		}
		if failed[s.Source.ID] {
			if exists && !snapshotEqual(previous, s) {
				return ErrInvalid
			}
			if !exists && (s.RetrievedAt != "" || len(s.Models) != 0) {
				return ErrInvalid
			}
		}
	}
	encoded, err := encodeDocument(proposal.Catalog)
	if err != nil {
		return ErrInvalid
	}
	var serialized Catalog
	if decode(encoded, &serialized, true) != nil || validateCatalog(serialized) != nil {
		return ErrInvalid
	}
	recheck := func() error {
		again, err := readProtected(sourcesPath, false)
		if err != nil || !bytes.Equal(authority, again) {
			return ErrConflict
		}
		again, err = readProtected(proposalPath, false)
		if err != nil || !bytes.Equal(data, again) {
			return ErrConflict
		}
		return nil
	}
	return writeAtomic(ctx, currentPath, encoded, expectedCurrent, recheck)
}
