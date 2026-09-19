package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupSignedBundleConfiguration struct {
	bundlePath, bundleDigest, publicKeyHex, signatureHex string
	bundleBytes                                          uint64
}
type setupSignedBundleExecutor func(context.Context, setupSignedBundleConfiguration) (string, error)
type setupSignedBundleProbe struct {
	configuration                                                      setupSignedBundleConfiguration
	planRoot, tenantID, repositoryID, recoveryOwner, authorityIdentity string
	execute                                                            setupSignedBundleExecutor
}

func deriveSetupSignedBundleAuthority(configuration setupSignedBundleConfiguration) (string, error) {
	return setupcore.SignedBundleAuthorityIdentity(configuration.bundleDigest, configuration.bundleBytes, configuration.publicKeyHex, configuration.signatureHex)
}
func digestSetupSignedBundle(value string) string {
	digest := sha256.Sum256([]byte("open-trestle/setup-signed-bundle/v1\x00" + value))
	return hex.EncodeToString(digest[:])
}
func validSetupSignedBundleConfiguration(configuration setupSignedBundleConfiguration) bool {
	if !validSetupBundlePath(configuration.bundlePath) {
		return false
	}
	_, err := deriveSetupSignedBundleAuthority(configuration)
	return err == nil
}
func newSetupSignedBundleProbe(plan setupcore.Plan, configuration setupSignedBundleConfiguration, execute setupSignedBundleExecutor) (*setupSignedBundleProbe, string, error) {
	if plan.Validate() != nil || execute == nil || !validSetupSignedBundleConfiguration(configuration) {
		return nil, "", errors.New("invalid signed bundle setup probe")
	}
	authority, err := deriveSetupSignedBundleAuthority(configuration)
	if err != nil {
		return nil, "", err
	}
	probe := &setupSignedBundleProbe{configuration: configuration, planRoot: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), recoveryOwner: plan.RecoveryOwner(), authorityIdentity: authority, execute: execute}
	if probe.ConfigurationIdentity() == "" {
		return nil, "", errors.New("invalid signed bundle setup probe")
	}
	return probe, authority, nil
}
func (p *setupSignedBundleProbe) AuthorityIdentity() string {
	if p == nil {
		return ""
	}
	authority, err := deriveSetupSignedBundleAuthority(p.configuration)
	if err != nil || authority != p.authorityIdentity {
		return ""
	}
	return authority
}
func (p *setupSignedBundleProbe) ConfigurationIdentity() string {
	if p == nil || p.planRoot == "" || p.tenantID == "" || p.repositoryID == "" || p.recoveryOwner == "" || !validSetupBundlePath(p.configuration.bundlePath) {
		return ""
	}
	authority := p.AuthorityIdentity()
	if authority == "" {
		return ""
	}
	return digestSetupSignedBundle("probe:" + authority + "\x00" + p.planRoot + "\x00" + p.tenantID + "\x00" + p.repositoryID + "\x00" + p.recoveryOwner + "\x00" + p.configuration.bundlePath + "\x00" + p.configuration.bundleDigest + "\x00" + strconv.FormatUint(p.configuration.bundleBytes, 10) + "\x00" + p.configuration.publicKeyHex + "\x00" + p.configuration.signatureHex)
}
func (p *setupSignedBundleProbe) Probe(ctx context.Context) setupcore.SignedBundleProbeResult {
	if p == nil || p.execute == nil || ctx == nil || ctx.Err() != nil || p.ConfigurationIdentity() == "" {
		return setupcore.NewInvalidSignedBundleProbeResult()
	}
	observation, err := p.execute(ctx, p.configuration)
	if ctx.Err() != nil || errors.Is(err, setupcore.ErrSignedBundleUnavailable) {
		return setupcore.NewUnavailableSignedBundleProbeResult()
	}
	if err != nil || !validAdminDigest(observation) {
		return setupcore.NewInvalidSignedBundleProbeResult()
	}
	return setupcore.NewVerifiedSignedBundleProbeResult(p.authorityIdentity, observation)
}
func (p *setupSignedBundleProbe) String() string { return "setup signed offline bundle probe" }
func (p *setupSignedBundleProbe) GoString() string {
	return "main.setupSignedBundleProbe{<redacted>}"
}
func (p *setupSignedBundleProbe) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, p.String(), p.GoString())
}
func executeSetupSignedBundle(ctx context.Context, configuration setupSignedBundleConfiguration) (string, error) {
	observation, err := setupcore.VerifySignedBundle(ctx, configuration.bundlePath, configuration.bundleDigest, configuration.bundleBytes, configuration.publicKeyHex, configuration.signatureHex)
	if err != nil {
		return "", err
	}
	if observation.Validate() != nil {
		return "", setupcore.ErrSignedBundleVerificationFailed
	}
	return observation.Identity(), nil
}
func validSetupBundlePath(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n") && filepath.IsAbs(value) && filepath.Clean(value) == value
}
