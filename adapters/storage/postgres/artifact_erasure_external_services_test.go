package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/georgejieh/open-trestle/adapters/keys/awskms"
	"github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

const erasureKeyARN = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4234-8234-123456789abc"

type erasureClock struct {
	mu      sync.Mutex
	at      time.Time
	samples int
	sql     *erasureSQLService
}

func (c *erasureClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples++
	if c.sql != nil {
		c.sql.mu.Lock()
		if len(c.sql.active) != 0 {
			_ = c.sql.fail("clock sampled inside SQL transaction")
		}
		c.sql.mu.Unlock()
	}
	return c.at
}
func (c *erasureClock) Set(at time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.at = at }
func (c *erasureClock) Samples() int     { c.mu.Lock(); defer c.mu.Unlock(); return c.samples }

type erasureExternalCounts struct{ Requests, Reads, Creates, Deletes, Generates, Decrypts int }
type erasureObjectVersion struct {
	ID, Digest string
	Content    []byte
}
type erasureObjectSnapshot map[string][]erasureObjectVersion
type erasureExternalServices struct {
	mu               sync.Mutex
	t                *testing.T
	sql              *erasureSQLService
	scope            audit.ReviewScope
	identity         string
	objects          erasureObjectSnapshot
	counts           erasureExternalCounts
	entered, release chan struct{}
	version          string
	generateError    error
	failures         []string
}

func newErasureExternalServices(t *testing.T, s *erasureSQLService, scope audit.ReviewScope, identity string) *erasureExternalServices {
	return &erasureExternalServices{t: t, sql: s, scope: scope, identity: identity, objects: erasureObjectSnapshot{}}
}
func (s *erasureExternalServices) Counts() erasureExternalCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts
}
func (s *erasureExternalServices) Snapshot() erasureObjectSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := erasureObjectSnapshot{}
	for key, versions := range s.objects {
		for _, v := range versions {
			v.Content = append([]byte(nil), v.Content...)
			out[key] = append(out[key], v)
		}
	}
	return out
}
func (s *erasureExternalServices) BlockNextCreate() (entered <-chan struct{}, release chan<- struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered = make(chan struct{})
	s.release = make(chan struct{})
	return s.entered, s.release
}
func erasureKnownCommitFor(events []erasureTraceEvent, graph, label string) bool {
	if graph == "" || label == "" {
		return false
	}
	for _, event := range events {
		if event.Graph == graph && event.OperationLabel == label && event.StatementID == "COMMIT" && event.ReplyKnown {
			return true
		}
	}
	return false
}
func TestErasureExternalCommitObservationIsScoped(t *testing.T) {
	cases := []struct {
		name   string
		events []erasureTraceEvent
		want   bool
	}{
		{"none", nil, false},
		{"verifier only", []erasureTraceEvent{{Graph: "first", OperationLabel: "verify-first", StatementID: "COMMIT", ReplyKnown: true}}, false},
		{"other graph", []erasureTraceEvent{{Graph: "second", OperationLabel: "work", StatementID: "COMMIT", ReplyKnown: true}}, false},
		{"unknown reply", []erasureTraceEvent{{Graph: "first", OperationLabel: "work", StatementID: "COMMIT", Persisted: true}}, false},
		{"not commit", []erasureTraceEvent{{Graph: "first", OperationLabel: "work", StatementID: "BEGIN", ReplyKnown: true}}, false},
		{"matching", []erasureTraceEvent{{Graph: "first", OperationLabel: "work", StatementID: "COMMIT", ReplyKnown: true}}, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := erasureKnownCommitFor(test.events, "first", "work"); got != test.want {
				t.Fatalf("scoped known commit=%v want=%v", got, test.want)
			}
		})
	}
	if erasureKnownCommitFor(cases[5].events, "", "work") || erasureKnownCommitFor(cases[5].events, "first", "") {
		t.Fatal("missing observation scope accepted")
	}
}

func (s *erasureExternalServices) observe(ctx context.Context, graph, kind string) error {
	s.mu.Lock()
	bounded := s.counts.Requests+s.counts.Generates+s.counts.Decrypts < 128
	s.mu.Unlock()
	if !bounded {
		return errors.New("external call bound")
	}
	s.sql.mu.Lock()
	defer s.sql.mu.Unlock()
	label := erasureLabel(ctx)
	for _, tx := range s.sql.active {
		if tx.label == label && tx.conn.graph == graph {
			return s.sql.fail("external effect inside SQL transaction")
		}
	}
	found := false
	for _, a := range s.sql.rows[erasureAdmissions] {
		if a["tenant_id"] == s.scope.TenantID() && a["artifact_identity"] == s.identity {
			found = true
		}
	}
	metadata := false
	for _, m := range s.sql.rows[erasureMetadata] {
		if m["tenant_id"] == s.scope.TenantID() && m["artifact_identity"] == s.identity {
			metadata = true
		}
	}
	if !found || !metadata {
		return s.sql.fail("external effect before durable metadata and canonical admission")
	}
	// A successful read transaction can establish knowledge of an earlier uncertain commit, but never creates a Put permit.
	known := erasureKnownCommitFor(s.sql.events, graph, label)
	if !known {
		return s.sql.fail("external effect before known commit reply")
	}
	s.sql.event(nil, kind, "external:"+graph+":"+label, false, false)
	return nil
}
func (s *erasureExternalServices) Backend(t *testing.T, graph string, clock artifact.ErasureClock) *s3.Backend {
	t.Helper()
	credentials, err := s3.NewCredentials("SYNTHETICACCESSKEY", "synthetic-secret-material-not-a-real-key-000000", "")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := s3.NewStaticCredentialsProvider(credentials)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := s3.New(s3.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Region: "us-east-1", Bucket: "synthetic-admission", Credentials: provider, HTTPClient: &http.Client{Transport: erasureRoundTripper{s, graph}, Timeout: 2 * time.Second}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return backend
}
func (s *erasureExternalServices) Keys(t *testing.T, graph string) *awskms.Provider {
	t.Helper()
	p, err := awskms.New(erasureKMSClient{s, graph}, "us-east-1", []awskms.TenantKey{{TenantID: s.scope.TenantID(), KeyARN: erasureKeyARN}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type erasureRoundTripper struct {
	s     *erasureExternalServices
	graph string
}

func (r erasureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s := r.s
	if err := s.observe(req.Context(), r.graph, "S3:"+req.Method); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.counts.Requests++
	switch req.Method {
	case http.MethodGet:
		s.counts.Reads++
	case http.MethodPut:
		s.counts.Creates++
	case http.MethodDelete:
		s.counts.Deletes++
	}
	s.mu.Unlock()
	key := strings.TrimPrefix(req.URL.Path, "/synthetic-admission/")
	payloadKey := "admission-fixture/artifacts/" + s.scope.Identity() + "/" + s.identity
	intent := "admission-fixture/deletions/" + s.scope.Identity() + "/" + s.identity + ".intent"
	receipt := strings.TrimSuffix(intent, ".intent") + ".receipt"
	if req.URL.Scheme != "https" || req.URL.Host != "s3.us-east-1.amazonaws.com" || req.URL.RawQuery != "" || (key != payloadKey && key != intent && key != receipt) || !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		return nil, errors.New("unexpected real S3 request")
	}
	s.mu.Lock()
	if s.counts.Requests+s.counts.Generates+s.counts.Decrypts > 128 {
		s.mu.Unlock()
		return nil, errors.New("external call bound")
	}
	if req.Method == http.MethodPut {
		entered, release := s.entered, s.release
		s.entered, s.release = nil, nil
		s.mu.Unlock()
		if entered != nil {
			close(entered)
			select {
			case <-release:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		s.mu.Lock()
	}
	defer s.mu.Unlock()
	headers := http.Header{}
	status := http.StatusOK
	var body []byte
	switch req.Method {
	case http.MethodGet:
		versions := s.objects[key]
		if len(versions) == 0 {
			status = http.StatusNotFound
			body = []byte("<Error><Code>NoSuchKey</Code></Error>")
		} else {
			v := versions[len(versions)-1]
			body = append([]byte(nil), v.Content...)
			version := v.ID
			if s.version != "" {
				version = s.version
			}
			headers.Set("x-amz-version-id", version)
			sum := sha256.Sum256(body)
			headers.Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(sum[:]))
		}
	case http.MethodPut:
		if key != payloadKey || req.Header.Get("If-None-Match") != "*" {
			return nil, errors.New("nonconditional Create")
		}
		data, err := io.ReadAll(io.LimitReader(req.Body, 65537))
		if err != nil || len(data) == 0 || len(data) > 65536 {
			return nil, errors.New("body bound")
		}
		sum := sha256.Sum256(data)
		if req.Header.Get("x-amz-checksum-sha256") != base64.StdEncoding.EncodeToString(sum[:]) || req.Header.Get("x-amz-content-sha256") != hex.EncodeToString(sum[:]) {
			return nil, errors.New("request checksum")
		}
		if len(s.objects[key]) > 0 {
			status = http.StatusPreconditionFailed
		} else {
			s.objects[key] = append(s.objects[key], erasureObjectVersion{ID: "synthetic-version-1", Digest: hex.EncodeToString(sum[:]), Content: append([]byte(nil), data...)})
		}
	case http.MethodDelete:
		return nil, errors.New("Delete is not admitted")
	default:
		return nil, errors.New("unexpected S3 method")
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
}

type erasureKMSClient struct {
	s     *erasureExternalServices
	graph string
}

func (k erasureKMSClient) binding(ctx context.Context, key *string, binding map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == nil || *key != erasureKeyARN {
		return errors.New("KMS key mismatch")
	}
	want := erasureHash([]byte("open-trestle/aws-kms-tenant/v1:" + k.s.scope.TenantID()))
	if !reflect.DeepEqual(binding, map[string]string{"open_trestle_tenant_binding": want}) {
		return errors.New("KMS tenant context mismatch")
	}
	return nil
}
func (k erasureKMSClient) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if err := k.s.observe(ctx, k.graph, "KMS:Generate"); err != nil {
		return nil, err
	}
	if err := k.binding(ctx, in.KeyId, in.EncryptionContext); err != nil {
		return nil, err
	}
	if in.KeySpec != types.DataKeySpecAes256 {
		return nil, errors.New("KMS key spec")
	}
	k.s.mu.Lock()
	k.s.counts.Generates++
	failure := k.s.generateError
	k.s.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	key := erasureKeyARN
	return &kms.GenerateDataKeyOutput{KeyId: &key, Plaintext: bytes.Repeat([]byte{0x31}, 32), CiphertextBlob: []byte("synthetic-wrapped-key-only")}, nil
}
func (k erasureKMSClient) Decrypt(ctx context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if err := k.s.observe(ctx, k.graph, "KMS:Decrypt"); err != nil {
		return nil, err
	}
	if err := k.binding(ctx, in.KeyId, in.EncryptionContext); err != nil {
		return nil, err
	}
	if in.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault || string(in.CiphertextBlob) != "synthetic-wrapped-key-only" {
		return nil, errors.New("KMS ciphertext binding")
	}
	k.s.mu.Lock()
	k.s.counts.Decrypts++
	k.s.mu.Unlock()
	key := erasureKeyARN
	return &kms.DecryptOutput{KeyId: &key, EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault, Plaintext: bytes.Repeat([]byte{0x31}, 32)}, nil
}
func erasureHash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func erasureProtectedFile(t *testing.T, b []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "authority.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func erasureOrdered(t *testing.T, fields map[string]any, order []string, domain string) []byte {
	t.Helper()
	var members []string
	for _, name := range order {
		if name == "identity" {
			continue
		}
		b, err := json.Marshal(fields[name])
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, fmt.Sprintf("%q:%s", name, b))
	}
	unsigned := []byte("{" + strings.Join(members, ",") + "}")
	fields["identity"] = erasureHash(append([]byte(domain), unsigned...))
	members = nil
	for _, name := range order {
		b, err := json.Marshal(fields[name])
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, fmt.Sprintf("%q:%s", name, b))
	}
	return []byte("{" + strings.Join(members, ",") + "}")
}

var erasurePolicyOrder = strings.Fields("contract schema_version identity namespace_identity backend_configuration_identity prefix namespace_epoch_identity backend_kind database_authority_identity namespace_mode protocol ownership fence_retention_policy_identity erasure_policy_identity recovery_policy_identity configuration_evidence_identity not_before_milliseconds not_after_milliseconds")

func erasurePolicy(t *testing.T, c erasureCatalog, backend *s3.Backend, changes map[string]any) artifact.ProtectedErasurePolicy {
	t.Helper()
	db, _ := json.Marshal(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Database  string `json:"database"`
		Schema    string `json:"schema"`
		Role      string `json:"role"`
		Namespace string `json:"namespace"`
	}{"open-trestle/postgresql-database-authority", 1, c.Database, c.Schema, c.Role, c.Namespace})
	namespace, err := artifact.NewStorageNamespace(backend.ConfigurationIdentity(), "admission-fixture", strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"contract": "open-trestle/protected-artifact-erasure-policy", "schema_version": 1, "namespace_identity": namespace.Identity(), "backend_configuration_identity": backend.ConfigurationIdentity(), "prefix": "admission-fixture", "namespace_epoch_identity": strings.Repeat("2", 64), "backend_kind": "aws_s3_general_purpose", "database_authority_identity": erasureHash(db), "namespace_mode": "protected_new_nonnull", "protocol": "same-key-fence-v2", "ownership": "all_versions_at_exact_key", "fence_retention_policy_identity": strings.Repeat("4", 64), "erasure_policy_identity": strings.Repeat("5", 64), "recovery_policy_identity": strings.Repeat("6", 64), "configuration_evidence_identity": strings.Repeat("7", 64), "not_before_milliseconds": int64(900), "not_after_milliseconds": int64(10000)}
	for key, value := range changes {
		fields[key] = value
	}
	encoded := erasureOrdered(t, fields, erasurePolicyOrder, "open-trestle/protected-artifact-erasure-policy/v1\x00")
	p, err := artifact.LoadProtectedErasurePolicy(context.Background(), erasureProtectedFile(t, encoded))
	if err != nil {
		t.Fatal("real policy loader", err)
	}
	return p
}
func erasureGrant(t *testing.T, p artifact.ProtectedErasurePolicy, a artifact.ArtifactAdmission, principal string) artifact.ErasureAuthorizationV2 {
	t.Helper()
	v, err := artifact.NewErasureAuthorizationV2(artifact.ErasureAuthorizationV2Options{Scope: a.Scope(), NamespaceIdentity: a.NamespaceIdentity(), ArtifactIdentity: a.ArtifactIdentity(), AdmissionIdentity: a.Identity(), PolicyIdentity: p.ErasurePolicyIdentity(), PrincipalIdentity: principal, HoldClearanceIdentity: strings.Repeat("9", 64), FenceRetentionPolicyIdentity: p.FenceRetentionPolicyIdentity(), Reason: artifact.DeletionTenantErasure, IssuedAt: time.UnixMilli(900).UTC(), ExpiresAt: time.UnixMilli(8000).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := artifact.EncodeErasureAuthorizationV2(v)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := artifact.LoadErasureAuthorizationV2(context.Background(), erasureProtectedFile(t, b), p)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}
func newErasureGraph(t *testing.T, s *erasureSQLService, ext *erasureExternalServices, policy artifact.ProtectedErasurePolicy, clock artifact.ErasureClock, name string) (*ArtifactIndex, *IndexedArtifactStore) {
	t.Helper()
	if observed, ok := clock.(*erasureClock); ok && observed != nil {
		observed.mu.Lock()
		observed.sql = s
		observed.mu.Unlock()
	}
	db := s.OpenDB(t, name)
	index, err := NewArtifactIndex(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := erasureOperationContext(t, "verify-"+name)
	defer cancel()
	w, err := VerifyArtifactErasureIndex(ctx, index)
	if err != nil {
		t.Fatal("real verifier prerequisite", err)
	}
	before := s.Snapshot()
	external := ext.Counts()
	store, err := NewIndexedEnvelopeStore(index, EnvelopeDependencies{Backend: ext.Backend(t, name, clock), Keys: ext.Keys(t, name), Clock: clock, IndexAuthority: w}, policy)
	if err != nil {
		t.Fatal("real factory", err)
	}
	if len(s.Snapshot().Events) != len(before.Events) || external != ext.Counts() {
		t.Fatal("constructor hidden I/O")
	}
	return index, store
}

type erasureFixture struct {
	t        *testing.T
	s        *erasureSQLService
	external *erasureExternalServices
	clock    *erasureClock
	policy   artifact.ProtectedErasurePolicy
	value    artifact.Artifact
	index    *ArtifactIndex
	store    *IndexedArtifactStore
	ctx      context.Context
}

func newErasureFixture(t *testing.T) *erasureFixture {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-admission", "repo-admission", "run-admission")
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindContextPacket, "text/plain", artifact.ClassificationRestricted, artifact.OriginMemory, artifact.ProtectionEnvelopeEncrypted, []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, []byte("synthetic admission payload"), time.UnixMilli(100).UTC(), time.UnixMilli(9000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	catalog := newErasureCatalog(t)
	service := newErasureSQLService(t, catalog)
	clock := &erasureClock{at: time.UnixMilli(1000).UTC()}
	ext := newErasureExternalServices(t, service, scope, value.Identity())
	p := erasurePolicy(t, catalog, ext.Backend(t, "setup", clock), nil)
	index, store := newErasureGraph(t, service, ext, p, clock, "first")
	ctx, cancel := erasureOperationContext(t, "work")
	t.Cleanup(cancel)
	t.Cleanup(func() { service.AssertClean(t) })
	return &erasureFixture{t, service, ext, clock, p, value, index, store, ctx}
}
func (f *erasureFixture) admission() artifact.ArtifactAdmission {
	f.t.Helper()
	a, found, err := f.store.ReadAdmission(f.ctx, f.value.Scope(), f.policy.NamespaceIdentity(), f.value.Identity())
	if err != nil || !found || a.Validate() != nil {
		f.t.Fatal("actual admission read", found, err)
	}
	return a
}
func (f *erasureFixture) put() {
	f.t.Helper()
	created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
	if err != nil || !created {
		f.t.Fatal("positive actual Put", created, err)
	}
}
func (f *erasureFixture) journal() *artifactAdmissionJournal {
	f.t.Helper()
	ctx, cancel := erasureOperationContext(f.t, "journal-verify")
	defer cancel()
	w, err := VerifyArtifactErasureIndex(ctx, f.index)
	if err != nil {
		f.t.Fatal(err)
	}
	j, err := newArtifactAdmissionJournal(f.index, w, f.policy, f.clock)
	if err != nil {
		f.t.Fatal(err)
	}
	return j
}
func erasureRequireZeroOperation(t *testing.T, o artifact.ErasureOperation) {
	t.Helper()
	if !reflect.DeepEqual(o, artifact.ErasureOperation{}) {
		t.Fatal("failure released operation metadata")
	}
}
func erasureRequireError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}
func erasureOnlyRow(t *testing.T, s *erasureSQLService, table string) erasureRow {
	t.Helper()
	rows := s.Snapshot().Rows[table]
	if len(rows) != 1 {
		t.Fatalf("%s rows=%d", table, len(rows))
	}
	return rows[0]
}
func erasureRowKey(r erasureRow) []driver.Value {
	return []driver.Value{r["tenant_id"], r["repository_id"], r["review_run_id"], r["artifact_identity"]}
}
