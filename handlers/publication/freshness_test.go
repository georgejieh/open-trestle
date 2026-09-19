package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	githubscm "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

type freshnessClock struct{ at time.Time }

func (c *freshnessClock) Now() time.Time { return c.at }

type freshnessCredentials struct {
	t             *testing.T
	scope         audit.ReviewScope
	target        review.PublicationTarget
	afterRetrieve func()
	calls         int
}

func (c *freshnessCredentials) RetrievePublicationToken(ctx context.Context, scope audit.ReviewScope, target review.PublicationTarget) (githubscm.Token, error) {
	c.t.Helper()
	if ctx.Err() != nil || scope.Identity() != c.scope.Identity() || target.Identity() != c.target.Identity() {
		c.t.Fatal("credential retrieval lost live exact-scope target authority")
	}
	c.calls++
	if c.afterRetrieve != nil {
		c.afterRetrieve()
	}
	return githubscm.NewToken([]byte("test-token"))
}

type freshnessGuard struct {
	t                   *testing.T
	scope               audit.ReviewScope
	operation, attempt  string
	afterClaim          func()
	claims, completions int
}

func (g *freshnessGuard) Identity() string { return strings.Repeat("f", 64) }
func (g *freshnessGuard) IdempotencyGuarantee() review.PublisherIdempotencyGuarantee {
	return review.PublisherExactOperationKey
}
func (g *freshnessGuard) ClaimPublicationAttempt(ctx context.Context, scope audit.ReviewScope, operation, attempt, digest string, at time.Time) (bool, error) {
	g.t.Helper()
	if ctx.Err() != nil || scope.Identity() != g.scope.Identity() || operation != g.operation || attempt != g.attempt || len(digest) != 64 || at.UnixMilli() <= 0 {
		g.t.Fatal("attempt guard lost exact request authority")
	}
	g.claims++
	if g.afterClaim != nil {
		g.afterClaim()
	}
	return g.claims == 1, nil
}
func (g *freshnessGuard) CompletePublicationAttempt(_ context.Context, scope audit.ReviewScope, attempt, result string, _ time.Time) error {
	g.t.Helper()
	if scope.Identity() != g.scope.Identity() || attempt != g.attempt || len(result) != 64 {
		g.t.Fatal("attempt completion lost exact authority")
	}
	g.completions++
	return nil
}

type freshnessGateLedger struct {
	audit.Ledger
	afterRecord func()
}

func (l freshnessGateLedger) Append(ctx context.Context, expected string, event audit.Event) error {
	if err := l.Ledger.Append(ctx, expected, event); err != nil {
		return err
	}
	if event.Kind() == audit.EventPublicationHeadReconciled {
		l.afterRecord()
	}
	return nil
}

type freshnessTransport func(*http.Request) (*http.Response, error)

func (f freshnessTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPublicationEffectTimeFreshness(t *testing.T) {
	for _, test := range []struct {
		name              string
		stage             string
		advance, lifetime time.Duration
		wantFailure       review.PublicationFailure
		checkDeadline     bool
	}{
		{name: "exact_authority", lifetime: time.Minute},
		{name: "gate_persistence_stale_head", stage: "gate", advance: 2001 * time.Millisecond, lifetime: time.Minute, wantFailure: review.PublicationFailureStaleHead},
		{name: "gate_persistence_expired_grant", stage: "gate", advance: 501 * time.Millisecond, lifetime: 500 * time.Millisecond, wantFailure: review.PublicationFailureAuthorization},
		{name: "guard_stale_head", stage: "guard", advance: 2001 * time.Millisecond, lifetime: time.Minute, wantFailure: review.PublicationFailureStaleHead},
		{name: "credentials_stale_head", stage: "credentials", advance: 2001 * time.Millisecond, lifetime: time.Minute, wantFailure: review.PublicationFailureStaleHead},
		{name: "guard_expired_grant", stage: "guard", advance: 501 * time.Millisecond, lifetime: 500 * time.Millisecond, wantFailure: review.PublicationFailureAuthorization},
		{name: "credentials_expired_grant", stage: "credentials", advance: 501 * time.Millisecond, lifetime: 500 * time.Millisecond, wantFailure: review.PublicationFailureAuthorization},
		{name: "remaining_head_deadline", stage: "credentials", advance: 100 * time.Millisecond, lifetime: time.Minute, checkDeadline: true},
		{name: "remaining_grant_deadline", stage: "credentials", advance: 100 * time.Millisecond, lifetime: 500 * time.Millisecond, checkDeadline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			at := time.UnixMilli(250)
			clock := &freshnessClock{at: at}
			scope, authorization, claim, attempt, ledger := freshnessPublicationFixture(t, at, test.lifetime)
			target := authorization.Plan().Target()
			credentials := &freshnessCredentials{t: t, scope: scope, target: target}
			guard := &freshnessGuard{t: t, scope: scope, operation: authorization.IdempotencyKey(), attempt: attempt.Identity()}
			gets, posts := 0, 0
			transport := freshnessTransport(func(request *http.Request) (*http.Response, error) {
				if request.Context().Err() != nil || request.URL.Host != "api.github.com" || request.Header.Get("Authorization") != "Bearer test-token" {
					t.Fatal("transport lost live exact endpoint credentials")
				}
				var body string
				switch request.Method {
				case http.MethodGet:
					gets++
					if request.URL.Path != "/repos/owner/repo/pulls/42" {
						t.Fatal("head lookup reached another target")
					}
					body = fmt.Sprintf(`{"head":{"sha":%q}}`, target.HeadRevision().Digest())
				case http.MethodPost:
					posts++
					if request.URL.Path != "/repos/owner/repo/pulls/42/reviews" {
						t.Fatal("publication reached another target")
					}
					var payload struct {
						CommitID string `json:"commit_id"`
						Event    string `json:"event"`
						Body     string `json:"body"`
					}
					if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					if payload.CommitID != target.HeadRevision().Digest() || payload.Event != "COMMENT" || !strings.Contains(payload.Body, "open-trestle-operation:"+authorization.IdempotencyKey()) {
						t.Fatal("publication payload lost commit or operation binding")
					}
					if test.checkDeadline {
						remaining := 2*time.Second - test.advance
						if grant := test.lifetime - test.advance; grant < remaining {
							remaining = grant
						}
						deadline, ok := request.Context().Deadline()
						if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > remaining {
							t.Errorf("HTTP deadline does not fit remaining publication authority: deadline=%v present=%t budget=%s", deadline, ok, remaining)
						}
					}
					body = fmt.Sprintf(`{"id":80,"commit_id":%q}`, target.HeadRevision().Digest())
				default:
					t.Fatalf("unexpected HTTP method %s", request.Method)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
			})
			adapter, err := githubscm.NewPublicationAdapter(githubscm.PublicationConfig{
				PublisherID: target.PublisherID(), RepositoryAuthority: "github.com", Credentials: credentials,
				CredentialIdentity: strings.Repeat("a", 64), AttemptGuard: guard,
				HTTPClient: &http.Client{Transport: transport, Timeout: 10 * time.Second}, HTTPClientIdentity: strings.Repeat("b", 64),
				Clock: clock, ClockIdentity: strings.Repeat("c", 64),
			})
			if err != nil {
				t.Fatal(err)
			}
			observation, err := review.ResolvePublicationHead(ctx, adapter, scope, authorization, claim, attempt, at)
			if err != nil {
				t.Fatal(err)
			}
			reconciliation, err := review.ReconcilePublicationHead(scope, authorization, claim, attempt, observation, at)
			if err != nil {
				t.Fatal(err)
			}
			advance := func() { clock.at = clock.at.Add(test.advance) }
			if test.stage == "gate" {
				ledger = freshnessGateLedger{Ledger: ledger, afterRecord: advance}
			}
			gate, err := review.RecordPublicationHeadReconciliation(ctx, ledger, scope, authorization, claim, attempt, reconciliation, at)
			if err != nil || !gate.AuthorizesPublication() {
				t.Fatalf("fresh recorded gate: %v", err)
			}
			switch test.stage {
			case "guard":
				guard.afterClaim = advance
			case "credentials":
				credentials.afterRetrieve = advance
			}
			result, err := review.DispatchClaimedPublication(ctx, adapter, scope, authorization, claim, attempt, gate, at)
			if err != nil {
				t.Fatalf("valid authorized dispatch did not reach adapter: %v", err)
			}
			if ctx.Err() != nil || guard.claims != 1 || gets != 1 {
				t.Fatalf("dispatch boundary not reached with live context: ctx=%v claims=%d gets=%d", ctx.Err(), guard.claims, gets)
			}
			if result.AuthorizationIdentity() != authorization.Identity() || result.ClaimIdentity() != claim.Identity() || result.AttemptIdentity() != attempt.Identity() || result.HeadReconciliationIdentity() != reconciliation.Identity() {
				t.Fatal("result lost authorized dispatch lineage")
			}
			if test.wantFailure != 0 {
				if posts != 0 || result.Status() != review.PublicationFailed || result.Failure() != test.wantFailure || guard.completions != 1 {
					t.Fatalf("stale authority must settle without POST: posts=%d status=%s failure=%s completions=%d", posts, result.Status(), result.Failure(), guard.completions)
				}
			} else if posts != 1 || result.Status() != review.PublicationSucceeded || credentials.calls != 2 || guard.completions != 1 {
				t.Fatalf("nominal publication: posts=%d status=%s credentials=%d completions=%d", posts, result.Status(), credentials.calls, guard.completions)
			}
			if test.name == "exact_authority" {
				repeated, err := review.DispatchClaimedPublication(ctx, adapter, scope, authorization, claim, attempt, gate, at)
				if err != nil || repeated.Status() != review.PublicationFailed || repeated.Failure() != review.PublicationFailureValidation || posts != 1 || guard.claims != 2 || credentials.calls != 2 || guard.completions != 1 {
					t.Fatalf("repeated authorized attempt escaped guard: err=%v status=%s posts=%d claims=%d credentials=%d completions=%d", err, repeated.Status(), posts, guard.claims, credentials.calls, guard.completions)
				}
			}
		})
	}
}

func freshnessPublicationFixture(t *testing.T, at time.Time, lifetime time.Duration) (audit.ReviewScope, review.PublicationAuthorization, review.PublicationClaim, review.PublicationAttemptAuthorization, audit.Ledger) {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	f := newSourceBindingFixture(t, false)
	item := f.input.EvidenceItems()[0]
	sourceRange := item.SourceRange()
	response := func(document string) provider.Response {
		part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
		check(err)
		value, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
		check(err)
		return value
	}
	candidateResponse := response(fmt.Sprintf(`{"schema_version":1,"candidates":[{"title":"Issue","claim":"The value is not checked.","severity_hint":"high","source_range":{"source_id":%q,"start_line":%d,"end_line":%d},"evidence_ids":[%q]}]}`, item.ID(), sourceRange.StartLine(), sourceRange.EndLine(), item.ID()))
	candidates, err := review.ParseCandidateBatch(candidateResponse, f.input.Snapshot(), f.input.EvidenceItems())
	check(err)
	generationRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", f.contextArtifact.Payload())
	check(err)
	generationAuthorization := f.input.Authorization()
	generationOutcome, err := gateway.NewSuccessfulRouteAttemptOutcome(generationAuthorization, candidates.ResponseIdentity(), provider.NewUnknownRouteTokenUsage(), 1)
	check(err)
	candidateOutput, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputCandidateBatch, f.input.ContextIdentity(), candidates.Identity(), generationRequest, generationAuthorization, generationOutcome)
	check(err)
	verificationContext, err := review.NewVerificationRequestContext(f.contextArtifact.Payload(), f.input.ContextIdentity(), f.scope.Identity(), f.input.MemoryScopeIdentity(), f.input.MemoryIdentity(), f.input.Snapshot(), f.input.EvidenceItems(), candidates)
	check(err)
	verificationResponse := response(fmt.Sprintf(`{"schema_version":1,"verdicts":[{"candidate_id":%q,"outcome":"verified","severity":"high","rationale":"The cited source confirms the issue.","evidence_ids":[%q]}]}`, candidates.Findings()[0].Identity(), item.ID()))
	verification, err := review.ParseVerificationBatch(verificationResponse, candidates, verificationContext.EvidenceItems())
	check(err)
	verificationRequest, err := verificationContext.ProviderRequest()
	check(err)
	verificationAuthorization := freshnessVerifierAuthorization(t, f.scope, verificationRequest)
	verificationOutcome, err := gateway.NewSuccessfulRouteAttemptOutcome(verificationAuthorization, verification.ResponseIdentity(), provider.NewUnknownRouteTokenUsage(), 1)
	check(err)
	verificationOutput, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputVerificationBatch, verificationContext.Identity(), verification.Identity(), verificationRequest, verificationAuthorization, verificationOutcome)
	check(err)
	independencePolicy, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	check(err)
	independence, err := gateway.VerifyIndependentRouteAttempts(independencePolicy, generationAuthorization, generationOutcome, verificationAuthorization, verificationOutcome)
	check(err)
	receipt, err := review.NewIndependentVerificationReceiptFromRecords(review.IndependentVerificationRecords{
		ReviewScopeIdentity: f.scope.Identity(), SnapshotIdentity: f.input.Snapshot().Identity(),
		GenerationContextIdentity: f.input.ContextIdentity(), VerificationContextIdentity: verificationContext.Identity(),
		GenerationRequestIdentity: generationRequest.Identity(), VerificationRequestIdentity: verificationRequest.Identity(),
		Candidates: candidates, CandidateOutput: candidateOutput, Verification: verification, VerificationOutput: verificationOutput, RouteIndependence: independence,
	})
	check(err)
	findings, err := review.PromoteVerifiedCandidates(receipt, candidates, verification)
	check(err)
	publicationPolicy, err := review.NewPublicationPolicy(review.SeverityMedium, 10, gateway.RouteIndependenceDistinctProvider, true)
	check(err)
	readiness, err := review.EvaluatePublicationReadiness(publicationPolicy, receipt, findings)
	check(err)
	handler := &Handler{store: f.store}
	binding, err := handler.buildSourceBinding(context.Background(), f.scope, f.target, artifact.Artifact{}, f.inputArtifact, f.contextArtifact, at)
	check(err)
	plan, err := review.NewPublicationPlanFromProtectedSource(readiness, f.target, binding)
	check(err)
	ledger := audit.NewMemoryLedger()
	_, err = review.RecordProtectedPublicationPrerequisites(context.Background(), ledger, f.scope, binding, readiness, at)
	check(err)
	effect, err := policy.NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), f.scope.Identity(), policy.CapabilityPublication, policy.DecisionAllow, policy.AuthorizationExplicitUserApproval, at, at.Add(lifetime))
	check(err)
	authorization, err := review.NewPublicationAuthorization(plan, effect, at)
	check(err)
	_, err = review.RecordPublicationAuthorization(context.Background(), ledger, f.scope, authorization, at)
	check(err)
	claim, claimed, err := review.ClaimPublication(context.Background(), ledger, f.scope, authorization, at)
	check(err)
	if !claimed {
		t.Fatal("publication claim not acquired")
	}
	attempt, err := review.NewInitialPublicationAttemptAuthorization(authorization, claim)
	check(err)
	return f.scope, authorization, claim, attempt, ledger
}

func freshnessVerifierAuthorization(t *testing.T, scope audit.ReviewScope, request provider.Request) gateway.RouteAttemptAuthorization {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	reference, err := provider.NewRouteReference(provider.ProviderZoneLocal, "verifier", "fake", "verifier-connection", "model-b", "v1")
	check(err)
	capabilities, err := provider.NewModelCapabilities(128000, 16000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	check(err)
	declaration, err := provider.NewRouteCapabilityDeclaration(reference, capabilities)
	check(err)
	pricing, err := provider.NewRoutePricing(0, 0)
	check(err)
	candidate, err := provider.NewRouteCandidateDeclaration(declaration, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier4)
	check(err)
	manifest := []byte("route evidence")
	digest := sha256.Sum256(manifest)
	record, err := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
	check(err)
	registry := bindingRouteRegistry{record: record, manifest: manifest}
	resolved, err := gateway.ResolveRouteRegistryRecord(context.Background(), record.Identity(), registry, registry)
	check(err)
	operational, err := provider.NewRouteOperationalState(record.Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	check(err)
	observed, err := gateway.NewObservedRouteCandidate(resolved, operational)
	check(err)
	requirements, err := provider.NewModelRequirements(1, 1, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	check(err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	check(err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	check(err)
	routing, err := gateway.NewReviewRoutingInput(scope, request, requirements, constraints)
	check(err)
	budget, err := provider.NewModelCostBudget(1, 16000, 0)
	check(err)
	eligibility, err := gateway.FilterEligibleRoutes(routing, budget, 1, []gateway.ObservedRouteCandidate{observed})
	check(err)
	rankingPolicy, err := gateway.NewRouteRankingPolicy(nil)
	check(err)
	performance, err := provider.NewUnknownRoutePerformanceObservation(record.Identity(), 1)
	check(err)
	ranking, err := gateway.RankEligibleRoutes(eligibility, rankingPolicy, 1, []provider.RoutePerformanceObservation{performance})
	check(err)
	selection, err := gateway.NewRouteSelectionReceipt(eligibility, ranking)
	check(err)
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
	check(err)
	return authorization
}
