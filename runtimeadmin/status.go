// Package runtimeadmin exposes authenticated, content-free runtime administration state.
package runtimeadmin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	maxRepositories  = 256
	maxHandlers      = 64
	maxComponents    = 64
	maxSnapshotBytes = 1 << 20
)

var (
	ErrInvalidConfiguration = errors.New("invalid runtime administration configuration")
	ErrInvalidService       = errors.New("invalid runtime administration service")
	ErrInvalidSnapshot      = errors.New("invalid runtime administration snapshot")
	ErrScopeNotConfigured   = errors.New("runtime administration scope not configured")
)

type MetadataBackend string

const (
	MetadataLocal    MetadataBackend = "local"
	MetadataPostgres MetadataBackend = "postgres"
)

type ArtifactBackend string

const (
	ArtifactLocal ArtifactBackend = "local"
	ArtifactS3    ArtifactBackend = "s3"
)

type Protection string

const (
	ProtectionProcessPrivate    Protection = "process_private"
	ProtectionEnvelopeEncrypted Protection = "envelope_encrypted"
)

type NotificationBackend string

const (
	NotificationProcessLocal NotificationBackend = "process_local"
	NotificationPostgres     NotificationBackend = "postgres"
)

// RateLimitBackend identifies process-local or shared request coordination.
type RateLimitBackend string

const (
	RateLimitProcessLocal RateLimitBackend = "process_local"
	RateLimitPostgres     RateLimitBackend = "postgres"
)

type ReviewMode string

const (
	ReviewDisabled ReviewMode = "disabled"
	ReviewLocal    ReviewMode = "local"
	ReviewAdvisory ReviewMode = "advisory"
	ReviewRequired ReviewMode = "required"
)

type ComponentState string

const (
	ComponentStarting ComponentState = "starting"
	ComponentReady    ComponentState = "ready"
)

type HandlerBinding struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
}
type ConfigurationOptions struct {
	TenantID                   string
	RepositoryIDs              []string
	MetadataBackend            MetadataBackend
	DatabaseAuthorityIdentity  string
	ArtifactBackend            ArtifactBackend
	ArtifactProtection         Protection
	NotificationBackend        NotificationBackend
	RateLimitBackend           RateLimitBackend
	RateLimitAuthorityIdentity string
	ReviewMode                 ReviewMode
	WebhookIngress             bool
	LocalWorkers               bool
	PublicationEnabled         bool
	PublicationFenceVerified   bool
	RouteInventoryIdentity     string
	RuntimePolicyIdentity      string
	RouteCount                 uint32
	Handlers                   []HandlerBinding
}
type Configuration struct {
	identity string
	options  ConfigurationOptions
}

func NewConfiguration(options ConfigurationOptions) (Configuration, error) {
	options.RepositoryIDs = append([]string(nil), options.RepositoryIDs...)
	options.Handlers = append([]HandlerBinding(nil), options.Handlers...)
	sort.Strings(options.RepositoryIDs)
	sort.Slice(options.Handlers, func(i, j int) bool {
		if options.Handlers[i].Kind == options.Handlers[j].Kind {
			return options.Handlers[i].Identity < options.Handlers[j].Identity
		}
		return options.Handlers[i].Kind < options.Handlers[j].Kind
	})
	configuration := Configuration{options: options}
	if !configuration.validContent() {
		return Configuration{}, ErrInvalidConfiguration
	}
	configuration.identity = configurationIdentity(options)
	return configuration, nil
}
func (c Configuration) Identity() string { return c.identity }
func (c Configuration) TenantID() string { return c.options.TenantID }
func (c Configuration) RepositoryIDs() []string {
	return append([]string(nil), c.options.RepositoryIDs...)
}
func (c Configuration) MetadataBackend() MetadataBackend  { return c.options.MetadataBackend }
func (c Configuration) DatabaseAuthorityIdentity() string { return c.options.DatabaseAuthorityIdentity }
func (c Configuration) ArtifactBackend() ArtifactBackend  { return c.options.ArtifactBackend }
func (c Configuration) ArtifactProtection() Protection    { return c.options.ArtifactProtection }
func (c Configuration) NotificationBackend() NotificationBackend {
	return c.options.NotificationBackend
}
func (c Configuration) RateLimitBackend() RateLimitBackend { return c.options.RateLimitBackend }
func (c Configuration) RateLimitAuthorityIdentity() string {
	return c.options.RateLimitAuthorityIdentity
}
func (c Configuration) ReviewMode() ReviewMode         { return c.options.ReviewMode }
func (c Configuration) WebhookIngress() bool           { return c.options.WebhookIngress }
func (c Configuration) LocalWorkers() bool             { return c.options.LocalWorkers }
func (c Configuration) PublicationEnabled() bool       { return c.options.PublicationEnabled }
func (c Configuration) PublicationFenceVerified() bool { return c.options.PublicationFenceVerified }
func (c Configuration) RouteInventoryIdentity() string { return c.options.RouteInventoryIdentity }
func (c Configuration) RuntimePolicyIdentity() string  { return c.options.RuntimePolicyIdentity }
func (c Configuration) RouteCount() uint32             { return c.options.RouteCount }
func (c Configuration) Handlers() []HandlerBinding {
	return append([]HandlerBinding(nil), c.options.Handlers...)
}
func (c Configuration) Validate() error {
	if !c.validContent() || c.identity != configurationIdentity(c.options) {
		return ErrInvalidConfiguration
	}
	return nil
}
func (c Configuration) validContent() bool {
	o := c.options
	if len(o.RepositoryIDs) == 0 || len(o.RepositoryIDs) > maxRepositories || !validScope(o.TenantID, "repository") || !sort.StringsAreSorted(o.RepositoryIDs) {
		return false
	}
	for i, r := range o.RepositoryIDs {
		if !validScope(o.TenantID, r) || (i > 0 && r == o.RepositoryIDs[i-1]) {
			return false
		}
	}
	if o.MetadataBackend != MetadataLocal && o.MetadataBackend != MetadataPostgres {
		return false
	}
	if o.MetadataBackend == MetadataPostgres && !nonzeroDigest(o.DatabaseAuthorityIdentity) || o.MetadataBackend == MetadataLocal && o.DatabaseAuthorityIdentity != "" {
		return false
	}
	if o.ArtifactBackend != ArtifactLocal && o.ArtifactBackend != ArtifactS3 {
		return false
	}
	if o.ArtifactProtection != ProtectionProcessPrivate && o.ArtifactProtection != ProtectionEnvelopeEncrypted {
		return false
	}
	if o.NotificationBackend != NotificationProcessLocal && o.NotificationBackend != NotificationPostgres {
		return false
	}
	if o.RateLimitBackend != RateLimitProcessLocal && o.RateLimitBackend != RateLimitPostgres {
		return false
	}
	if o.RateLimitBackend == RateLimitPostgres && (o.MetadataBackend != MetadataPostgres || !nonzeroDigest(o.RateLimitAuthorityIdentity)) || o.RateLimitBackend == RateLimitProcessLocal && o.RateLimitAuthorityIdentity != "" {
		return false
	}
	if o.ReviewMode != ReviewDisabled && o.ReviewMode != ReviewLocal && o.ReviewMode != ReviewAdvisory && o.ReviewMode != ReviewRequired {
		return false
	}
	if o.MetadataBackend == MetadataLocal && (o.ArtifactBackend != ArtifactLocal || o.ArtifactProtection != ProtectionProcessPrivate || o.NotificationBackend != NotificationProcessLocal || o.RateLimitBackend != RateLimitProcessLocal) {
		return false
	}
	if o.ArtifactBackend == ArtifactLocal && o.ArtifactProtection != ProtectionProcessPrivate || o.ArtifactBackend == ArtifactS3 && (o.MetadataBackend != MetadataPostgres || o.ArtifactProtection != ProtectionEnvelopeEncrypted) {
		return false
	}
	if o.NotificationBackend == NotificationPostgres && o.MetadataBackend != MetadataPostgres {
		return false
	}
	if o.MetadataBackend == MetadataPostgres && o.RateLimitBackend != RateLimitPostgres {
		return false
	}
	runtimeConfigured := o.RouteInventoryIdentity != "" || o.RuntimePolicyIdentity != "" || o.RouteCount != 0
	if runtimeConfigured && (!nonzeroDigest(o.RouteInventoryIdentity) || !nonzeroDigest(o.RuntimePolicyIdentity) || o.RouteCount == 0 || o.RouteCount > 64 || !o.LocalWorkers) {
		return false
	}
	if !runtimeConfigured && (o.RouteInventoryIdentity != "" || o.RuntimePolicyIdentity != "" || o.RouteCount != 0) {
		return false
	}
	if o.PublicationEnabled != (o.ReviewMode == ReviewRequired) || o.PublicationEnabled && !o.PublicationFenceVerified || o.PublicationFenceVerified && o.MetadataBackend != MetadataPostgres {
		return false
	}
	if o.ReviewMode == ReviewDisabled && (o.LocalWorkers || len(o.Handlers) > 0 || runtimeConfigured) {
		return false
	}
	if o.LocalWorkers && len(o.Handlers) == 0 || len(o.Handlers) > maxHandlers {
		return false
	}
	for i, h := range o.Handlers {
		if !validTaskKind(h.Kind) || !nonzeroDigest(h.Identity) || (i > 0 && h.Kind == o.Handlers[i-1].Kind) {
			return false
		}
	}
	return true
}

type configurationWire struct {
	TenantID                   string              `json:"tenant_id"`
	RepositoryIDs              []string            `json:"repository_ids"`
	MetadataBackend            MetadataBackend     `json:"metadata_backend"`
	DatabaseAuthorityIdentity  string              `json:"database_authority_identity,omitempty"`
	ArtifactBackend            ArtifactBackend     `json:"artifact_backend"`
	ArtifactProtection         Protection          `json:"artifact_protection"`
	NotificationBackend        NotificationBackend `json:"notification_backend"`
	RateLimitBackend           RateLimitBackend    `json:"rate_limit_backend"`
	RateLimitAuthorityIdentity string              `json:"rate_limit_authority_identity,omitempty"`
	ReviewMode                 ReviewMode          `json:"review_mode"`
	WebhookIngress             bool                `json:"webhook_ingress"`
	LocalWorkers               bool                `json:"local_workers"`
	PublicationEnabled         bool                `json:"publication_enabled"`
	PublicationFenceVerified   bool                `json:"publication_fence_verified"`
	RouteInventoryIdentity     string              `json:"route_inventory_identity,omitempty"`
	RuntimePolicyIdentity      string              `json:"runtime_policy_identity,omitempty"`
	RouteCount                 uint32              `json:"route_count"`
	Handlers                   []HandlerBinding    `json:"handlers"`
}

func wireConfiguration(o ConfigurationOptions) configurationWire {
	return configurationWire{TenantID: o.TenantID, RepositoryIDs: append([]string(nil), o.RepositoryIDs...), MetadataBackend: o.MetadataBackend, DatabaseAuthorityIdentity: o.DatabaseAuthorityIdentity, ArtifactBackend: o.ArtifactBackend, ArtifactProtection: o.ArtifactProtection, NotificationBackend: o.NotificationBackend, RateLimitBackend: o.RateLimitBackend, RateLimitAuthorityIdentity: o.RateLimitAuthorityIdentity, ReviewMode: o.ReviewMode, WebhookIngress: o.WebhookIngress, LocalWorkers: o.LocalWorkers, PublicationEnabled: o.PublicationEnabled, PublicationFenceVerified: o.PublicationFenceVerified, RouteInventoryIdentity: o.RouteInventoryIdentity, RuntimePolicyIdentity: o.RuntimePolicyIdentity, RouteCount: o.RouteCount, Handlers: append([]HandlerBinding(nil), o.Handlers...)}
}
func configurationIdentity(o ConfigurationOptions) string {
	encoded, _ := json.Marshal(wireConfiguration(o))
	sum := sha256.Sum256(append([]byte("open-trestle/runtime-configuration/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

type ReadinessProbe struct {
	Name  string
	Ready <-chan struct{}
}
type Service struct {
	configuration Configuration
	probes        []ReadinessProbe
}

func NewService(configuration Configuration, probes []ReadinessProbe) (*Service, error) {
	if configuration.Validate() != nil || len(probes) > maxComponents {
		return nil, ErrInvalidService
	}
	canonical := append([]ReadinessProbe(nil), probes...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Name < canonical[j].Name })
	for i, p := range canonical {
		if !validName(p.Name) || p.Ready == nil || (i > 0 && p.Name == canonical[i-1].Name) {
			return nil, ErrInvalidService
		}
	}
	return &Service{configuration: configuration, probes: canonical}, nil
}

type Component struct {
	name  string
	state ComponentState
}

func (c Component) Name() string          { return c.name }
func (c Component) State() ComponentState { return c.state }

type Snapshot struct {
	identity, configurationIdentity, tenantID, repositoryID string
	observedAt                                              time.Time
	ready                                                   bool
	configuration                                           Configuration
	components                                              []Component
}

func (s Snapshot) Identity() string              { return s.identity }
func (s Snapshot) ConfigurationIdentity() string { return s.configurationIdentity }
func (s Snapshot) TenantID() string              { return s.tenantID }
func (s Snapshot) RepositoryID() string          { return s.repositoryID }
func (s Snapshot) ObservedAt() time.Time         { return s.observedAt }
func (s Snapshot) Ready() bool                   { return s.ready }
func (s Snapshot) Configuration() Configuration  { return s.configuration }
func (s Snapshot) Components() []Component       { return append([]Component(nil), s.components...) }
func (s *Service) Snapshot(tenantID, repositoryID string, at time.Time) (Snapshot, error) {
	if s == nil || s.configuration.Validate() != nil || tenantID != s.configuration.TenantID() || !contains(s.configuration.RepositoryIDs(), repositoryID) {
		return Snapshot{}, ErrScopeNotConfigured
	}
	if at.IsZero() || at.Year() < 1970 || at.Year() > 9999 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	at = at.UTC().Truncate(time.Millisecond)
	components := make([]Component, len(s.probes))
	ready := true
	for i, p := range s.probes {
		state := ComponentStarting
		select {
		case <-p.Ready:
			state = ComponentReady
		default:
			ready = false
		}
		components[i] = Component{name: p.Name, state: state}
	}
	publicOptions := s.configuration.options
	publicOptions.RepositoryIDs = []string{repositoryID}
	publicConfiguration, err := NewConfiguration(publicOptions)
	if err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	value := Snapshot{configurationIdentity: publicConfiguration.Identity(), tenantID: tenantID, repositoryID: repositoryID, observedAt: at, ready: ready, configuration: publicConfiguration, components: components}
	value.identity = snapshotIdentity(value)
	return value, nil
}

type componentWire struct {
	Name  string         `json:"name"`
	State ComponentState `json:"state"`
}
type snapshotWire struct {
	Contract              string            `json:"contract"`
	SchemaVersion         int               `json:"schema_version"`
	Identity              string            `json:"identity"`
	ConfigurationIdentity string            `json:"configuration_identity"`
	TenantID              string            `json:"tenant_id"`
	RepositoryID          string            `json:"repository_id"`
	ObservedAt            string            `json:"observed_at"`
	Ready                 bool              `json:"ready"`
	Configuration         configurationWire `json:"configuration"`
	Components            []componentWire   `json:"components"`
}

func wireSnapshot(s Snapshot, identity bool) snapshotWire {
	components := make([]componentWire, len(s.components))
	for i, c := range s.components {
		components[i] = componentWire{c.name, c.state}
	}
	id := ""
	if identity {
		id = s.identity
	}
	return snapshotWire{"open-trestle/runtime-status", 1, id, s.configurationIdentity, s.tenantID, s.repositoryID, s.observedAt.Format(time.RFC3339Nano), s.ready, wireConfiguration(s.configuration.options), components}
}
func snapshotIdentity(s Snapshot) string {
	wire := wireSnapshot(s, false)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	sum := sha256.Sum256(append([]byte("open-trestle/runtime-status/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}
func (s Snapshot) Validate() error {
	if s.configuration.Validate() != nil || s.configurationIdentity != s.configuration.Identity() || s.tenantID != s.configuration.TenantID() || len(s.configuration.RepositoryIDs()) != 1 || s.configuration.RepositoryIDs()[0] != s.repositoryID || s.observedAt.Location() != time.UTC || s.observedAt.Year() < 1970 || s.observedAt.Year() > 9999 || s.observedAt.Nanosecond()%int(time.Millisecond) != 0 || len(s.components) > maxComponents {
		return ErrInvalidSnapshot
	}
	ready := true
	for i, c := range s.components {
		if !validName(c.name) || (c.state != ComponentStarting && c.state != ComponentReady) || (i > 0 && c.name <= s.components[i-1].name) {
			return ErrInvalidSnapshot
		}
		ready = ready && c.state == ComponentReady
	}
	if ready != s.ready || s.identity != snapshotIdentity(s) {
		return ErrInvalidSnapshot
	}
	return nil
}
func (s Snapshot) MarshalJSON() ([]byte, error) {
	if s.Validate() != nil {
		return nil, ErrInvalidSnapshot
	}
	return json.Marshal(wireSnapshot(s, true))
}
func DecodeSnapshot(payload []byte) (Snapshot, error) {
	if len(payload) == 0 || len(payload) > maxSnapshotBytes {
		return Snapshot{}, ErrInvalidSnapshot
	}
	var wire snapshotWire
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) == nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	options := ConfigurationOptions{TenantID: wire.Configuration.TenantID, RepositoryIDs: wire.Configuration.RepositoryIDs, MetadataBackend: wire.Configuration.MetadataBackend, DatabaseAuthorityIdentity: wire.Configuration.DatabaseAuthorityIdentity, ArtifactBackend: wire.Configuration.ArtifactBackend, ArtifactProtection: wire.Configuration.ArtifactProtection, NotificationBackend: wire.Configuration.NotificationBackend, RateLimitBackend: wire.Configuration.RateLimitBackend, RateLimitAuthorityIdentity: wire.Configuration.RateLimitAuthorityIdentity, ReviewMode: wire.Configuration.ReviewMode, WebhookIngress: wire.Configuration.WebhookIngress, LocalWorkers: wire.Configuration.LocalWorkers, PublicationEnabled: wire.Configuration.PublicationEnabled, PublicationFenceVerified: wire.Configuration.PublicationFenceVerified, RouteInventoryIdentity: wire.Configuration.RouteInventoryIdentity, RuntimePolicyIdentity: wire.Configuration.RuntimePolicyIdentity, RouteCount: wire.Configuration.RouteCount, Handlers: wire.Configuration.Handlers}
	configuration, err := NewConfiguration(options)
	if err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	at, err := time.Parse(time.RFC3339Nano, wire.ObservedAt)
	if err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	components := make([]Component, len(wire.Components))
	for i, c := range wire.Components {
		components[i] = Component{c.Name, c.State}
	}
	snapshot := Snapshot{identity: wire.Identity, configurationIdentity: wire.ConfigurationIdentity, tenantID: wire.TenantID, repositoryID: wire.RepositoryID, observedAt: at, ready: wire.Ready, configuration: configuration, components: components}
	if wire.Contract != "open-trestle/runtime-status" || wire.SchemaVersion != 1 || snapshot.Validate() != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	canonical, _ := json.Marshal(snapshot)
	if !bytes.Equal(bytes.TrimSpace(payload), canonical) {
		return Snapshot{}, ErrInvalidSnapshot
	}
	return snapshot, nil
}
func validScope(tenant, repository string) bool {
	_, err := audit.NewReviewScope(tenant, repository, "runtime-status")
	return err == nil
}
func validTaskKind(value string) bool {
	switch value {
	case "acquire_source", "build_change", "inspect_deterministic", "retrieve_context", "assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication", "publish_result":
		return true
	}
	return false
}
func validName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func nonzeroDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}
func contains(values []string, value string) bool {
	i := sort.SearchStrings(values, value)
	return i < len(values) && values[i] == value
}
func (c Configuration) String() string   { return "runtime administration configuration" }
func (c Configuration) GoString() string { return "runtimeadmin.Configuration{<redacted>}" }
func (c Configuration) Format(state fmt.State, verb rune) {
	writeFormat(state, verb, c.String(), c.GoString())
}
func (s Snapshot) String() string   { return "runtime administration snapshot" }
func (s Snapshot) GoString() string { return "runtimeadmin.Snapshot{<redacted>}" }
func (s Snapshot) Format(state fmt.State, verb rune) {
	writeFormat(state, verb, s.String(), s.GoString())
}
func writeFormat(state fmt.State, verb rune, plain, goValue string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = goValue
	}
	_, _ = state.Write([]byte(value))
}
