package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
	"github.com/georgejieh/open-trestle/setuphttp"
	webconsole "github.com/georgejieh/open-trestle/web"
)

const defaultSetupWebAddress = "127.0.0.1:8742"

type setupWebHandler struct {
	handler     http.Handler
	permissions *setupGitHubPermissionSession
	lifetime    context.Context
	cancel      context.CancelFunc
}

func (h *setupWebHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h == nil || h.lifetime == nil || h.lifetime.Err() != nil || h.handler == nil {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	h.handler.ServeHTTP(writer, request)
}

func (h *setupWebHandler) Close() error {
	if h == nil {
		return nil
	}
	if h.cancel != nil {
		h.cancel()
	}
	return h.permissions.Close()
}

func newSetupWebHandler(lifetime context.Context, statePath, token string, environment func(string) string, clock setupClock, authority string, githubConfiguration setupGitHubPermissionHostConfiguration) (*setupWebHandler, error) {
	if setupGitHubPermissionNil(lifetime) || environment == nil || setupGitHubPermissionNil(clock) || !validSetupWebAddress(authority) || githubConfiguration.Validate() != nil {
		return nil, githubadapter.ErrInvalidBrokerConfig
	}
	if lifetime.Err() != nil {
		return nil, githubadapter.ErrBrokerUnavailable
	}
	owned, cancel := context.WithCancel(lifetime)
	h := &setupWebHandler{lifetime: owned, cancel: cancel}
	constructed := false
	defer func() {
		if !constructed {
			_ = h.Close()
		}
	}()
	if githubConfiguration.configured {
		var err error
		h.permissions, err = newSetupGitHubPermissionSession(owned, githubConfiguration.broker, environment, githubadapter.SystemBrokerClock{})
		if err != nil {
			return nil, err
		}
	}
	inferenceFactory, factoryErr := newSetupLocalInferenceFactory(environment)
	if factoryErr != nil {
		return nil, factoryErr
	}
	postgresProbe, probeErr := newSetupPostgresStorageProbe(environment, executeSetupPostgresStorage)
	if probeErr != nil {
		return nil, probeErr
	}
	secretBuilder := setuphttp.SecretBackendProbeBuilder(func(tenant, region, keyARN, endpoint string) (setupcore.SecretBackendProbe, error) {
		probe, _, err := newSetupKMSProbe(environment, tenant, region, keyARN, endpoint, executeSetupKMS)
		return probe, err
	})
	envelopeBuilder := setuphttp.EnvelopeStorageProbeBuilder(func(plan setupcore.Plan, s3Endpoint, s3Region, s3Bucket, s3Prefix, kmsRegion, kmsKeyARN, kmsEndpoint string) (setupcore.EnvelopeStorageProbe, error) {
		configuration := setupEnvelopeConfiguration{tenantID: plan.TenantID(), s3Endpoint: s3Endpoint, s3Region: s3Region, s3Bucket: s3Bucket, s3Prefix: s3Prefix, kmsRegion: kmsRegion, kmsKeyARN: kmsKeyARN, kmsEndpoint: kmsEndpoint}
		probe, _, err := newSetupEnvelopeStorageProbe(environment, plan, configuration, executeSetupEnvelopeStorage)
		return probe, err
	})
	integrationBuilder := setuphttp.IntegrationPermissionProbeBuilder(func(plan setupcore.Plan, expectedBrokerAuthority string, allowTokenCreation bool) (setupcore.IntegrationPermissionProbe, error) {
		configuration := setupGitHubPermissionConfiguration{host: githubConfiguration, session: h.permissions, expectedBrokerAuthority: expectedBrokerAuthority, allowTokenCreation: allowTokenCreation}
		probe, _, err := newSetupGitHubPermissionProbe(environment, plan, configuration, executeSetupGitHubPermission)
		return probe, err
	})
	webhookBuilder := setuphttp.WebhookProbeBuilder(func(plan setupcore.Plan, keyID string) (setupcore.WebhookProbe, error) {
		probe, _, err := newSetupGitHubWebhookProbe(environment, plan, keyID, executeSetupGitHubWebhook)
		return probe, err
	})
	sharedRateLimitBuilder := setuphttp.SharedRateLimitProbeBuilder(func(plan setupcore.Plan, databaseAuthorityIdentity string) (setupcore.SharedRateLimitProbe, error) {
		probe, _, err := newSetupSharedRateLimitProbe(environment, plan, databaseAuthorityIdentity, executeSetupSharedRateLimit)
		return probe, err
	})
	replicaReconciliationBuilder := setuphttp.ReplicaReconciliationProbeBuilder(func(plan setupcore.Plan, databaseAuthorityIdentity string) (setupcore.ReplicaReconciliationProbe, error) {
		probe, _, err := newSetupReplicaReconciliationProbe(environment, plan, databaseAuthorityIdentity, executeSetupReplicaReconciliation)
		return probe, err
	})
	signedBundleBuilder := setuphttp.SignedBundleProbeBuilder(func(plan setupcore.Plan, path, digest string, bytes uint64, publicKey, signature string) (setupcore.SignedBundleProbe, error) {
		configuration := setupSignedBundleConfiguration{bundlePath: path, bundleDigest: digest, bundleBytes: bytes, publicKeyHex: publicKey, signatureHex: signature}
		probe, _, err := newSetupSignedBundleProbe(plan, configuration, executeSetupSignedBundle)
		return probe, err
	})
	api, err := setuphttp.New(setuphttp.Options{StatePath: statePath, Token: token, Environment: environment, LocalInferenceFactory: inferenceFactory, PostgresProbe: postgresProbe, SecretBackendProbeBuilder: secretBuilder, EnvelopeStorageProbeBuilder: envelopeBuilder, IntegrationPermissionProbeBuilder: integrationBuilder, WebhookProbeBuilder: webhookBuilder, SharedRateLimitProbeBuilder: sharedRateLimitBuilder, ReplicaReconciliationProbeBuilder: replicaReconciliationBuilder, SignedBundleProbeBuilder: signedBundleBuilder, Clock: clock})
	if err != nil {
		return nil, err
	}
	console := webconsole.NewHandler()
	mux := http.NewServeMux()
	mux.Handle("/api/v1/setup", api)
	mux.Handle("/api/v1/setup/", api)
	mux.Handle("/console", console)
	mux.Handle("/console/", console)
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		if request.URL.Path != "/" {
			http.NotFound(writer, request)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(writer, request, "/console/setup", http.StatusTemporaryRedirect)
	})
	h.handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request == nil || request.Host != authority {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			http.Error(writer, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(writer, request)
	})
	constructed = true
	return h, nil
}

type setupWebListen func(string, string) (net.Listener, error)

func runSetupWeb(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	return runSetupWebWithListener(ctx, args, getenv, stdout, stderr, net.Listen)
}
func runSetupWebWithListener(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, listen setupWebListen) (exitCode int) {
	if setupGitHubPermissionNil(ctx) || getenv == nil || setupGitHubPermissionNil(stdout) || setupGitHubPermissionNil(stderr) || listen == nil {
		return 2
	}
	flags := flag.NewFlagSet("trestle setup web", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "protected setup state file")
	address := flags.String("listen", defaultSetupWebAddress, "numeric loopback listen address")
	approveGitHubBroker := flags.String("approve-github-source-broker-authority-identity", "", "exact host approval for protected source broker configuration")
	if flags.Parse(args) != nil {
		return 2
	}
	token := getenv("OPEN_TRESTLE_SETUP_TOKEN")
	if flags.NArg() != 0 || *statePath == "" || !validSetupWebAddress(*address) || token == "" {
		writeSetupWebUsage(stderr)
		return 2
	}
	brokerPath := getenv("OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG")
	staticToken := ""
	if brokerPath != "" {
		staticToken = getenv("OPEN_TRESTLE_GITHUB_API_TOKEN")
	}
	githubHost, err := loadSetupGitHubPermissionHostConfiguration(ctx, brokerPath, *approveGitHubBroker, staticToken)
	staticToken = ""
	if err != nil {
		fmt.Fprintln(stderr, "setup web failed")
		return 2
	}
	handler, err := newSetupWebHandler(ctx, *statePath, token, getenv, systemSetupClock{}, *address, githubHost)
	if err != nil {
		fmt.Fprintln(stderr, "setup web failed")
		return 2
	}
	defer func() {
		if handler.Close() != nil {
			fmt.Fprintln(stderr, "setup credential cleanup failed")
			exitCode = 1
		}
	}()
	listener, err := listen("tcp", *address)
	if err != nil {
		fmt.Fprintln(stderr, "setup web failed")
		return 1
	}
	actual := listener.Addr().String()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 105 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 64 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	defer func() {
		handler.cancel()
		_ = server.Close()
	}()
	if _, err = fmt.Fprintf(stdout, "setup web available at http://%s/console/setup\n", actual); err != nil {
		_ = listener.Close()
		return 1
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err = <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		fmt.Fprintln(stderr, "setup web failed")
		return 1
	case <-ctx.Done():
		handler.cancel()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		shutdownErr := server.Shutdown(shutdownContext)
		cancel()
		if shutdownErr != nil {
			_ = server.Close()
		}
		serveErr := <-result
		if shutdownErr != nil || serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "setup web failed")
			return 1
		}
		return 0
	}
}
func validSetupWebAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() || address.String() != host {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535 && strconv.Itoa(port) == portText && value == net.JoinHostPort(host, portText)
}
func writeSetupWebUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: OPEN_TRESTLE_SETUP_TOKEN=TOKEN trestle setup web --state PATH [--listen LOOPBACK:PORT] [--approve-github-source-broker-authority-identity HEX64] (required host cap when OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG is set)")
}
