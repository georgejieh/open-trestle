// Package spending keeps Open Trestle's local spending limits and usage ledger
// for the API keys a review uses.
//
// Every figure it records is an upper-bound estimate, not a bill: a review's
// cost is the provider-reported tokens priced at the route's declared price,
// which for OpenRouter is the highest price among the pinned endpoints, or,
// when usage is unknown, the cost reserved for each request sent. A limit is
// best effort. Concurrent runs, other tools that use the same key and
// provider price changes are invisible to it, so the provider's own limit is
// the guarantee.
//
// A limit is scoped by provider ID and the credential reference identity of
// the key variable, the identity every setup records for that variable name,
// so every setup that names the same variable shares one limit. Records never
// hold an API key, source, prompts or model replies.
package spending

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const (
	// LimitContract names a spending limit record.
	LimitContract = "open-trestle/spending-limit"
	// EntryContract names one usage ledger entry.
	EntryContract = "open-trestle/usage-ledger-entry"
	// PriceBasisRouteMaxPrice says that an entry's cost is priced at the
	// route's declared price, the highest pinned endpoint price: an
	// upper-bound estimate, not a bill.
	PriceBasisRouteMaxPrice = "route_max_price"
	// CostSettledUsage is an entry whose cost was settled from the
	// provider-reported usage of every request.
	CostSettledUsage = "settled_usage"
	// CostReservationUpperBound is an entry whose usage was not known for every
	// request, so each such request counts at the cost reserved for it.
	CostReservationUpperBound = "reservation_upper_bound"

	// MaxLimitMicroUSD is the largest limit a record admits ($1,000,000).
	MaxLimitMicroUSD uint64 = 1_000_000 * 1_000_000
	// MaxEntryCostMicroUSD bounds one entry's cost ($1,000,000,000), far above
	// any review a per-request budget admits.
	MaxEntryCostMicroUSD uint64 = 1_000_000_000 * 1_000_000
	// MaxRequestsSent bounds the requests one entry counts.
	MaxRequestsSent = 1000

	maxScopes       = 8
	maxModels       = 8
	maxAlerts       = 8
	maxLimitBytes   = 4 << 10
	maxEntryBytes   = 8 << 10
	microUSDPerCent = 10_000
)

var (
	// ErrInvalidRecord is a limit or entry that is malformed, not canonical or
	// out of bounds.
	ErrInvalidRecord = errors.New("invalid spending record")
	// ErrInvalidScope is a provider ID or key variable name that cannot key a
	// limit.
	ErrInvalidScope = errors.New("invalid spending limit scope")
)

// Period is a calendar period in UTC, matching providers' resets.
type Period string

const (
	PeriodWeek  Period = "week"
	PeriodMonth Period = "month"
	PeriodYear  Period = "year"
)

// ParsePeriod accepts exactly week, month or year.
func ParsePeriod(value string) (Period, error) {
	switch period := Period(value); period {
	case PeriodWeek, PeriodMonth, PeriodYear:
		return period, nil
	}
	return "", fmt.Errorf("%w: the period must be week, month or year", ErrInvalidRecord)
}

// Bounds returns the calendar period that contains at, in UTC: a week from
// Monday 00:00, a month from its first day, a year from 1 January. The end
// is exclusive.
func (p Period) Bounds(at time.Time) (start, end time.Time) {
	at = at.UTC()
	day := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
	switch p {
	case PeriodWeek:
		start = day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7))
		return start, start.AddDate(0, 0, 7)
	case PeriodYear:
		start = time.Date(at.Year(), time.January, 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(1, 0, 0)
	default:
		start = time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0)
	}
}

// Adjective is "weekly", "monthly" or "annual".
func (p Period) Adjective() string {
	switch p {
	case PeriodWeek:
		return "weekly"
	case PeriodYear:
		return "annual"
	}
	return "monthly"
}

// Current is "this week", "this month" or "this year".
func (p Period) Current() string { return "this " + string(p) }

// Scope keys a limit: the provider ID and the key variable name. The variable
// name is not a secret; its value, the key, is never read here.
type Scope struct {
	ProviderID            string
	CredentialEnvironment string
}

// NewScope validates a provider ID and key variable name.
func NewScope(providerID, credentialEnvironment string) (Scope, error) {
	scope := Scope{ProviderID: providerID, CredentialEnvironment: credentialEnvironment}
	if !validProviderID(providerID) || !runtimeconfig.ValidCredentialEnvironment(credentialEnvironment) {
		return Scope{}, ErrInvalidScope
	}
	return scope, nil
}

// CredentialReferenceIdentity is the identity setup records for the key
// variable name.
func (s Scope) CredentialReferenceIdentity() string {
	identity, _ := runtimeconfig.CredentialReferenceIdentity(s.CredentialEnvironment)
	return identity
}

// key names the scope's limit file: a digest of the provider ID and the
// credential reference identity.
func (s Scope) key() string {
	sum := sha256.Sum256([]byte("open-trestle/spending-scope/v1/" + s.ProviderID + "/" + s.CredentialReferenceIdentity()))
	return hex.EncodeToString(sum[:])
}

func (s Scope) valid() bool {
	_, err := NewScope(s.ProviderID, s.CredentialEnvironment)
	return err == nil
}

func compareScopes(a, b Scope) int {
	if c := strings.Compare(a.CredentialEnvironment, b.CredentialEnvironment); c != 0 {
		return c
	}
	return strings.Compare(a.ProviderID, b.ProviderID)
}

func validProviderID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || i > 0 && (r == '-' || r == '_' || r == '.')) {
			return false
		}
	}
	return true
}

type scopeWire struct {
	ProviderID                  string `json:"provider_id"`
	CredentialEnvironment       string `json:"credential_environment"`
	CredentialReferenceIdentity string `json:"credential_reference_identity"`
}

func wireScope(s Scope) scopeWire {
	return scopeWire{ProviderID: s.ProviderID, CredentialEnvironment: s.CredentialEnvironment, CredentialReferenceIdentity: s.CredentialReferenceIdentity()}
}

func (w scopeWire) scope() (Scope, error) {
	scope, err := NewScope(w.ProviderID, w.CredentialEnvironment)
	if err != nil || w.CredentialReferenceIdentity != scope.CredentialReferenceIdentity() {
		return Scope{}, ErrInvalidRecord
	}
	return scope, nil
}

// Limit is one key's spending limit: an amount per calendar period, with the
// percentages at which a review prints an alert.
type Limit struct {
	Scope          Scope
	Period         Period
	AmountMicroUSD uint64
	AlertPercents  []int
	SetAt          time.Time
}

// DefaultAlertPercents alert at 80% and at the limit.
var DefaultAlertPercents = []int{80, 100}

// NewLimit validates a limit. The amount is whole cents from $0.01 to
// MaxLimitMicroUSD; alerts are 1 to 8 ascending percentages from 1 to 100.
func NewLimit(scope Scope, period Period, amountMicroUSD uint64, alerts []int, setAt time.Time) (Limit, error) {
	limit := Limit{Scope: scope, Period: period, AmountMicroUSD: amountMicroUSD, AlertPercents: slices.Clone(alerts), SetAt: setAt.UTC().Truncate(time.Second)}
	if !scope.valid() {
		return Limit{}, ErrInvalidScope
	}
	if _, err := ParsePeriod(string(period)); err != nil {
		return Limit{}, err
	}
	if amountMicroUSD < microUSDPerCent || amountMicroUSD > MaxLimitMicroUSD || amountMicroUSD%microUSDPerCent != 0 {
		return Limit{}, fmt.Errorf("%w: the limit must be whole cents from $0.01 to $1,000,000.00", ErrInvalidRecord)
	}
	if len(alerts) == 0 || len(alerts) > maxAlerts {
		return Limit{}, fmt.Errorf("%w: give from 1 to %d alert percentages", ErrInvalidRecord, maxAlerts)
	}
	for i, percent := range alerts {
		if percent < 1 || percent > 100 || i > 0 && percent <= alerts[i-1] {
			return Limit{}, fmt.Errorf("%w: alert percentages must be ascending whole numbers from 1 to 100", ErrInvalidRecord)
		}
	}
	if limit.SetAt.Year() < 2000 || limit.SetAt.Year() > 9999 {
		return Limit{}, ErrInvalidRecord
	}
	return limit, nil
}

type limitWire struct {
	Contract      string `json:"contract"`
	SchemaVersion int    `json:"schema_version"`
	scopeWire
	Period        string `json:"period"`
	LimitMicroUSD uint64 `json:"limit_micro_usd"`
	AlertPercents []int  `json:"alert_percents"`
	SetAt         string `json:"set_at"`
}

// EncodeLimit writes the canonical record: one JSON object and a newline.
func EncodeLimit(limit Limit) ([]byte, error) {
	if _, err := NewLimit(limit.Scope, limit.Period, limit.AmountMicroUSD, limit.AlertPercents, limit.SetAt); err != nil {
		return nil, err
	}
	return encodeCanonical(limitWire{Contract: LimitContract, SchemaVersion: 1, scopeWire: wireScope(limit.Scope), Period: string(limit.Period), LimitMicroUSD: limit.AmountMicroUSD, AlertPercents: limit.AlertPercents, SetAt: formatTime(limit.SetAt)})
}

// ParseLimit reads exactly the canonical bytes EncodeLimit writes.
func ParseLimit(encoded []byte) (Limit, error) {
	var wire limitWire
	if err := decodeCanonical(encoded, maxLimitBytes, &wire); err != nil || wire.Contract != LimitContract || wire.SchemaVersion != 1 {
		return Limit{}, ErrInvalidRecord
	}
	scope, err := wire.scope()
	if err != nil {
		return Limit{}, err
	}
	setAt, err := parseTime(wire.SetAt)
	if err != nil {
		return Limit{}, err
	}
	limit, err := NewLimit(scope, Period(wire.Period), wire.LimitMicroUSD, wire.AlertPercents, setAt)
	if err != nil {
		return Limit{}, ErrInvalidRecord
	}
	return limit, nil
}

// Entry is one review run's spend: the requests it sent through keyed
// routes and their cost, the settled cost when usage was known for every
// request and otherwise the reservation upper bound.
type Entry struct {
	RecordedAt            time.Time
	ReviewRunID           string
	RuntimePolicyIdentity string
	// Scopes are the keys the review's routes use. When they differ, each is
	// charged the whole cost, so every key's total stays an upper bound.
	Scopes       []Scope
	Models       []string
	RequestsSent uint32
	UsageKnown   bool
	CostMicroUSD uint64
}

// CostKind is CostSettledUsage or CostReservationUpperBound.
func (e Entry) CostKind() string {
	if e.UsageKnown {
		return CostSettledUsage
	}
	return CostReservationUpperBound
}

// Charges reports whether the entry counts against scope.
func (e Entry) Charges(scope Scope) bool {
	return slices.ContainsFunc(e.Scopes, func(s Scope) bool { return s == scope })
}

type entryWire struct {
	Contract              string      `json:"contract"`
	SchemaVersion         int         `json:"schema_version"`
	RecordedAt            string      `json:"recorded_at"`
	ReviewRunID           string      `json:"review_run_id"`
	RuntimePolicyIdentity string      `json:"runtime_policy_identity"`
	Keys                  []scopeWire `json:"keys"`
	Models                []string    `json:"models"`
	RequestsSent          uint32      `json:"requests_sent"`
	UsageKnown            bool        `json:"usage_known"`
	CostMicroUSD          uint64      `json:"cost_micro_usd"`
	Cost                  string      `json:"cost"`
	PriceBasis            string      `json:"price_basis"`
}

// NewEntry validates an entry and puts its keys and models in canonical
// sorted order.
func NewEntry(entry Entry) (Entry, error) {
	entry.RecordedAt = entry.RecordedAt.UTC().Truncate(time.Second)
	entry.Scopes = slices.Clone(entry.Scopes)
	slices.SortFunc(entry.Scopes, compareScopes)
	entry.Models = slices.Clone(entry.Models)
	slices.Sort(entry.Models)
	if entry.RecordedAt.Year() < 2000 || entry.RecordedAt.Year() > 9999 || !validRunID(entry.ReviewRunID) || !validDigest(entry.RuntimePolicyIdentity) {
		return Entry{}, ErrInvalidRecord
	}
	if len(entry.Scopes) == 0 || len(entry.Scopes) > maxScopes || len(entry.Models) == 0 || len(entry.Models) > maxModels {
		return Entry{}, ErrInvalidRecord
	}
	for i, scope := range entry.Scopes {
		if !scope.valid() || i > 0 && compareScopes(entry.Scopes[i-1], scope) == 0 {
			return Entry{}, ErrInvalidRecord
		}
	}
	for i, model := range entry.Models {
		if !validModel(model) || i > 0 && entry.Models[i-1] == model {
			return Entry{}, ErrInvalidRecord
		}
	}
	if entry.RequestsSent == 0 || entry.RequestsSent > MaxRequestsSent || entry.CostMicroUSD > MaxEntryCostMicroUSD {
		return Entry{}, ErrInvalidRecord
	}
	return entry, nil
}

// EncodeEntry writes one canonical ledger line, newline included.
func EncodeEntry(entry Entry) ([]byte, error) {
	entry, err := NewEntry(entry)
	if err != nil {
		return nil, err
	}
	keys := make([]scopeWire, len(entry.Scopes))
	for i, scope := range entry.Scopes {
		keys[i] = wireScope(scope)
	}
	encoded, err := encodeCanonical(entryWire{Contract: EntryContract, SchemaVersion: 1, RecordedAt: formatTime(entry.RecordedAt), ReviewRunID: entry.ReviewRunID, RuntimePolicyIdentity: entry.RuntimePolicyIdentity, Keys: keys, Models: entry.Models, RequestsSent: entry.RequestsSent, UsageKnown: entry.UsageKnown, CostMicroUSD: entry.CostMicroUSD, Cost: entry.CostKind(), PriceBasis: PriceBasisRouteMaxPrice})
	if err != nil || len(encoded) > maxEntryBytes {
		return nil, ErrInvalidRecord
	}
	return encoded, nil
}

// ParseEntry reads exactly one canonical ledger line, newline included.
func ParseEntry(encoded []byte) (Entry, error) {
	var wire entryWire
	if err := decodeCanonical(encoded, maxEntryBytes, &wire); err != nil || wire.Contract != EntryContract || wire.SchemaVersion != 1 || wire.PriceBasis != PriceBasisRouteMaxPrice {
		return Entry{}, ErrInvalidRecord
	}
	recordedAt, err := parseTime(wire.RecordedAt)
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{RecordedAt: recordedAt, ReviewRunID: wire.ReviewRunID, RuntimePolicyIdentity: wire.RuntimePolicyIdentity, Models: wire.Models, RequestsSent: wire.RequestsSent, UsageKnown: wire.UsageKnown, CostMicroUSD: wire.CostMicroUSD}
	for _, key := range wire.Keys {
		scope, err := key.scope()
		if err != nil {
			return Entry{}, err
		}
		entry.Scopes = append(entry.Scopes, scope)
	}
	if wire.Cost != entry.CostKind() {
		return Entry{}, ErrInvalidRecord
	}
	normalized, err := NewEntry(entry)
	if err != nil {
		return Entry{}, err
	}
	// Canonical bytes list keys and models sorted; an unsorted line is not
	// what EncodeEntry writes.
	if !slices.Equal(normalized.Models, entry.Models) || !slices.Equal(normalized.Scopes, entry.Scopes) {
		return Entry{}, ErrInvalidRecord
	}
	return normalized, nil
}

func validRunID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func validModel(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

func formatTime(at time.Time) string { return at.UTC().Format(time.RFC3339) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalidRecord
	}
	return parsed, nil
}

// encodeCanonical is the one JSON form records use: compact, in struct field
// order, without HTML escaping, with a final newline.
func encodeCanonical(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil, ErrInvalidRecord
	}
	return buffer.Bytes(), nil
}

// decodeCanonical admits a record only when it decodes strictly (no unknown
// field, one value) and re-encodes to exactly the same bytes, which also
// refuses duplicate members, reordering and non-canonical numbers.
func decodeCanonical(encoded []byte, limit int, target any) error {
	if len(encoded) == 0 || len(encoded) > limit || encoded[len(encoded)-1] != '\n' || !utf8.Valid(encoded) {
		return ErrInvalidRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrInvalidRecord
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidRecord
	}
	again, err := encodeCanonical(target)
	if err != nil || !bytes.Equal(again, encoded) {
		return ErrInvalidRecord
	}
	return nil
}
