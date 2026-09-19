package postgres

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
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

const resumeOwner = "123456789012"
const resumeBucket = "synthetic-resume"
const resumeRegion = "us-east-1"
const resumeSecret = "synthetic-secret-not-provider-material-00000000"
const resumePrefix = "resume-fixture"

type resumeClock struct {
	mu                    sync.Mutex
	at                    time.Time
	samples               int
	sql                   *resumeFixtureSQLService
	graph                 string
	afterKnownReservation time.Time
}

func (c *resumeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples++
	if c.sql != nil {
		c.sql.mu.Lock()
		for _, tx := range c.sql.active {
			if tx.conn.graph == c.graph {
				_ = c.sql.fail("clock inside owning graph transaction")
			}
		}
		if !c.afterKnownReservation.IsZero() {
			for _, e := range c.sql.events {
				if e.Graph == c.graph && e.StatementID == "attempt_insert" && resumeCommitted(c.sql.events, e.Graph, e.OperationLabel, e.TransactionID) {
					c.at = c.afterKnownReservation
					break
				}
			}
		}
		c.sql.mu.Unlock()
	}
	if c.samples > 32768 {
		return time.Time{}
	}
	return c.at
}
func (c *resumeClock) Set(at time.Time) { c.mu.Lock(); c.at = at; c.mu.Unlock() }
func (c *resumeClock) Value() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *resumeClock) Samples() int     { c.mu.Lock(); defer c.mu.Unlock(); return c.samples }

type resumePeerVersion struct {
	ID     string
	Marker bool
	Body   []byte
}

// ResponseBody is the intended server body, not evidence of full client receipt.
type resumeWireEvent struct {
	Graph, Invocation, Method, Key, Query, Digest, Attempt string
	Transaction                                            uint64
	Body                                                   []byte
	Header                                                 http.Header
	Sequence                                               int
	MaximumResponse                                        uint32
	ResponseBody                                           []byte
	ResponseStatus                                         int
	SQLSequence                                            uint64
}
type resumePeerFault struct {
	Method, Key, Graph string
	Occurrence, seen   int
	Status             int
	Body               []byte
	Headers            http.Header
	Lose               bool
	Before, After      bool
	ListOnly           bool
	Entered            chan struct{}
	Release            chan struct{}
	once               *sync.Once
}
type resumeGraphAuthority struct {
	access, label       string
	scope               audit.ReviewScope
	identity            string
	kmsCalls            int
	disableKMS          bool
	generateError       error
	reservedInvocations map[string]bool
}
type resumePeer struct {
	mu                               sync.Mutex
	t                                *testing.T
	sql                              *resumeFixtureSQLService
	listener                         *net.TCPListener
	ca                               []byte
	certificate                      tls.Certificate
	deadline                         time.Time
	done                             chan struct{}
	stopOnce                         sync.Once
	connections                      map[net.Conn]bool
	graphs                           map[string]*resumeGraphAuthority
	access                           map[string]string
	used                             map[string]bool
	objects                          map[string][]resumePeerVersion
	events                           []resumeWireEvent
	faults                           []*resumePeerFault
	failures                         []string
	requestBodyLimit, replyBodyLimit int
	totalBody, nextVersion           int
}

func resumeHash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

type resumePeerBodyProfile struct {
	RequestBodyBytes int
	ReplyBodyBytes   int
}

const resumePeerHeaderFramingBytes = 32 << 10

func newResumePeer(t *testing.T, s *resumeFixtureSQLService) *resumePeer {
	t.Helper()
	return newResumePeerWithBodyProfile(t, s, resumePeerBodyProfile{RequestBodyBytes: 1 << 20, ReplyBodyBytes: 2 << 20})
}
func newResumePeerWithBodyProfile(t *testing.T, s *resumeFixtureSQLService, profile resumePeerBodyProfile) *resumePeer {
	t.Helper()
	if profile.RequestBodyBytes <= 0 || profile.RequestBodyBytes > 32<<20 || profile.ReplyBodyBytes <= 0 || profile.ReplyBodyBytes > 32<<20 {
		t.Fatal("invalid finite resume peer body profile")
	}
	now := time.Now()
	deadline := now.Add(15 * time.Minute)
	if testDeadline, ok := t.Deadline(); ok && testDeadline.Before(deadline) {
		deadline = testDeadline
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	p := &resumePeer{t: t, sql: s, listener: ln, ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate: tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey}, deadline: deadline, done: make(chan struct{}), connections: map[net.Conn]bool{}, graphs: map[string]*resumeGraphAuthority{}, access: map[string]string{}, used: map[string]bool{}, objects: map[string][]resumePeerVersion{}, requestBodyLimit: profile.RequestBodyBytes, replyBodyLimit: profile.ReplyBodyBytes}
	if err := ln.SetDeadline(p.deadline); err != nil {
		t.Fatal(err)
	}
	go p.serve()
	t.Cleanup(func() {
		p.Stop(t)
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.failures) != 0 {
			t.Errorf("external peer failures: %v", p.failures)
		}
	})
	return p
}
func (p *resumePeer) serve() {
	var workers sync.WaitGroup
	defer func() { workers.Wait(); close(p.done) }()
	for n := 0; n < 8192; n++ {
		raw, err := p.listener.AcceptTCP()
		if err != nil {
			return
		}
		_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
		p.mu.Lock()
		p.connections[raw] = true
		p.mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer raw.Close()
			defer func() { p.mu.Lock(); delete(p.connections, raw); p.mu.Unlock() }()
			conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{p.certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
			ctx, cancel := context.WithDeadline(context.Background(), p.deadline)
			defer cancel()
			if err := conn.HandshakeContext(ctx); err != nil {
				return
			}
			req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(conn, int64(p.requestBodyLimit)+resumePeerHeaderFramingBytes)))
			if err != nil {
				return
			}
			body, err := io.ReadAll(io.LimitReader(req.Body, int64(p.requestBodyLimit)+1))
			closeErr := req.Body.Close()
			if err != nil || closeErr != nil || len(body) > p.requestBodyLimit {
				p.fail("request body bound")
				return
			}
			if req.Proto != "HTTP/1.1" || !req.Close {
				p.fail("owned connection profile")
				return
			}
			event, err := p.authenticate(req, body)
			if err != nil {
				p.fail(err.Error())
				return
			}
			if err := p.authorize(&event); err != nil {
				p.fail(err.Error())
				return
			}
			p.mu.Lock()
			event.Sequence = len(p.events) + 1
			p.events = append(p.events, event)
			p.totalBody += len(body)
			if len(p.events) > 8192 || p.totalBody > 128<<20 {
				p.failures = append(p.failures, "peer root bound")
				p.mu.Unlock()
				return
			}
			var fault *resumePeerFault
			for _, f := range p.faults {
				if (f.Method == "" || f.Method == event.Method) && (f.Key == "" || f.Key == event.Key) && (f.Graph == "" || f.Graph == event.Graph) && (!f.ListOnly || req.URL.Query().Has("versions")) {
					f.seen++
					if f.seen == f.Occurrence {
						fault = f
						break
					}
				}
			}
			p.mu.Unlock()
			if fault != nil && fault.Before {
				if !p.barrier(fault) {
					return
				}
			}
			status, headers, data := 0, http.Header{}, []byte(nil)
			if fault != nil && (fault.Status == 403 || fault.Status == 405 || fault.Status == 409 || fault.Status == 412) {
				status = fault.Status
				data = []byte("<Error><Code>AccessDenied</Code></Error>")
			} else {
				status, headers, data = p.objectReply(event, req.URL.Query())
			}
			if fault != nil && fault.After {
				if !p.barrier(fault) {
					return
				}
			}
			if fault != nil {
				if fault.Lose {
					_ = raw.SetLinger(0)
					return
				}
				if fault.Status != 0 {
					status = fault.Status
				}
				if fault.Body != nil {
					data = append([]byte(nil), fault.Body...)
				}
				for k, v := range fault.Headers {
					headers[k] = append([]string(nil), v...)
				}
			}
			if len(data) > p.replyBodyLimit {
				p.fail("reply body bound")
				return
			}
			p.mu.Lock()
			p.totalBody += len(data)
			p.events[event.Sequence-1].ResponseBody = append([]byte(nil), data...)
			p.events[event.Sequence-1].ResponseStatus = status
			if p.totalBody > 128<<20 {
				p.failures = append(p.failures, "aggregate wire body bound")
				p.mu.Unlock()
				return
			}
			p.mu.Unlock()
			// A client may close after its body cap. Write errors do not fail this fixture.
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n", status, http.StatusText(status), len(data))
			_ = headers.Write(conn)
			_, _ = io.WriteString(conn, "\r\n")
			_, _ = conn.Write(data)
		}()
	}
	p.fail("connection cap")
}
func (p *resumePeer) fail(s string) { p.mu.Lock(); p.failures = append(p.failures, s); p.mu.Unlock() }
func (p *resumePeer) barrier(f *resumePeerFault) bool {
	f.once.Do(func() { close(f.Entered) })
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-f.Release:
		return true
	case <-timer.C:
		p.fail("barrier deadline")
		return false
	case <-p.done:
		return false
	}
}
func (p *resumePeer) Stop(t *testing.T) {
	t.Helper()
	p.stopOnce.Do(func() {
		_ = p.listener.Close()
		p.mu.Lock()
		for _, f := range p.faults {
			if f.Release != nil {
				select {
				case <-f.Release:
				default:
					close(f.Release)
				}
			}
		}
		for conn := range p.connections {
			_ = conn.Close()
		}
		p.mu.Unlock()
	})
	timer := time.NewTimer(21 * time.Second)
	defer timer.Stop()
	select {
	case <-p.done:
	case <-timer.C:
		t.Fatal("TLS workers did not join")
	}
}
func (p *resumePeer) Fault(f resumePeerFault) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.Occurrence < 1 {
		panic("fault occurrence")
	}
	f.once = new(sync.Once) // Each registered fault owns its barrier signal.
	p.faults = append(p.faults, &f)
}
func (p *resumePeer) Events() []resumeWireEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]resumeWireEvent(nil), p.events...)
}
func (p *resumePeer) History(key string) []resumePeerVersion {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append([]resumePeerVersion(nil), p.objects[key]...)
	for i := range out {
		out[i].Body = append([]byte(nil), out[i].Body...)
	}
	return out
}
func (p *resumePeer) AddHistory(t *testing.T, key string, marker bool, body []byte) string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.objects[key]) == 0 {
		t.Fatal("historical fixture requires actual payload insertion")
	}
	p.nextVersion++
	id := fmt.Sprintf("historical-%05d", p.nextVersion)
	p.objects[key] = append(p.objects[key], resumePeerVersion{id, marker, append([]byte(nil), body...)})
	return id
}
func (p *resumePeer) backend(t *testing.T, name string, scope audit.ReviewScope, identity string) *s3.ErasureBackend {
	t.Helper()
	p.mu.Lock()
	if _, ok := p.graphs[name]; ok {
		p.mu.Unlock()
		t.Fatal("duplicate graph")
	}
	access := "SYNTHETIC" + strings.ToUpper(resumeHash([]byte(name))[:20])
	p.graphs[name] = &resumeGraphAuthority{access: access, scope: scope, identity: identity}
	p.access[access] = name
	p.mu.Unlock()
	credentials, err := s3.NewCredentials(access, resumeSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := s3.NewErasureBackend(s3.ErasureConfig{Endpoint: "https://" + p.listener.Addr().String(), Region: resumeRegion, Bucket: resumeBucket, Credentials: credentials, TrustedCAPEM: append([]byte(nil), p.ca...)})
	if err != nil {
		t.Fatal(err)
	}
	return backend
}
func (p *resumePeer) authenticate(req *http.Request, body []byte) (resumeWireEvent, error) {
	bad := func() (resumeWireEvent, error) { return resumeWireEvent{}, errors.New("independent SigV4 binding") }
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") {
		return bad()
	}
	parts := strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 Credential="), ", ")
	if len(parts) != 3 {
		return bad()
	}
	credential := strings.Split(parts[0], "/")
	if len(credential) != 5 {
		return bad()
	}
	p.mu.Lock()
	graph := p.access[credential[0]]
	g := p.graphs[graph]
	label := ""
	if g != nil {
		label = g.label
	}
	p.mu.Unlock()
	if graph == "" || credential[2] != resumeRegion || credential[3] != "s3" || credential[4] != "aws4_request" {
		return bad()
	}
	at, err := time.Parse("20060102T150405Z", req.Header.Get("X-Amz-Date"))
	if err != nil || time.Since(at) > time.Minute || time.Until(at) > time.Minute || credential[1] != at.Format("20060102") {
		return bad()
	}
	if req.Host != p.listener.Addr().String() || req.Header.Get("X-Amz-Content-Sha256") != resumeHash(body) || req.URL.RawQuery != strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20") {
		return bad()
	}
	signed := strings.TrimPrefix(parts[1], "SignedHeaders=")
	names := strings.Split(signed, ";")
	if !sort.StringsAreSorted(names) {
		return bad()
	}
	seen := map[string]bool{}
	var headers strings.Builder
	for _, name := range names {
		if seen[name] || name != strings.ToLower(name) {
			return bad()
		}
		seen[name] = true
		values := req.Header.Values(name)
		if name == "host" {
			values = []string{req.Host}
		}
		if len(values) != 1 {
			return bad()
		}
		headers.WriteString(name + ":" + strings.Join(strings.Fields(values[0]), " ") + "\n")
	}
	for _, h := range []string{"host", "x-amz-date", "x-amz-content-sha256"} {
		if !seen[h] {
			return bad()
		}
	}
	for _, h := range []string{"Range", "Cookie", "Trailer", "Upgrade", "X-Amz-Bypass-Governance-Retention", "Idempotency-Key"} {
		if req.Header.Get(h) != "" {
			return bad()
		}
	}
	if req.Header.Get("X-Amz-Expected-Bucket-Owner") != "" && !seen["x-amz-expected-bucket-owner"] {
		return bad()
	}
	if req.Header.Get("X-Amz-Expected-Bucket-Owner") != "" && req.Method == "GET" && !req.URL.Query().Has("versions") && (!seen["x-amz-checksum-mode"] || req.Header.Get("X-Amz-Checksum-Mode") != "ENABLED") {
		return bad()
	}
	if req.Method == "PUT" && (!seen["content-type"] || !seen["x-amz-checksum-sha256"] || req.Header.Get("Content-Type") != "application/octet-stream" || !seen["if-none-match"] || req.Header.Get("If-None-Match") != "*" || req.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(resumeSHA(body))) {
		return bad()
	}
	canonical := strings.Join([]string{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, headers.String(), signed, resumeHash(body)}, "\n")
	scope := strings.Join(credential[1:], "/")
	toSign := "AWS4-HMAC-SHA256\n" + req.Header.Get("X-Amz-Date") + "\n" + scope + "\n" + resumeHash([]byte(canonical))
	mac := func(key []byte, v string) []byte {
		m := hmac.New(sha256.New, key)
		_, _ = m.Write([]byte(v))
		return m.Sum(nil)
	}
	key := mac([]byte("AWS4"+resumeSecret), credential[1])
	for _, v := range []string{resumeRegion, "s3", "aws4_request"} {
		key = mac(key, v)
	}
	if parts[2] != "Signature="+hex.EncodeToString(mac(key, toSign)) {
		return bad()
	}
	objectKey := strings.TrimPrefix(req.URL.Path, "/"+resumeBucket+"/")
	if req.URL.Path == "/"+resumeBucket {
		objectKey = req.URL.Query().Get("prefix")
	}
	return resumeWireEvent{Graph: graph, Invocation: label, Method: req.Method, Key: objectKey, Query: req.URL.RawQuery, Digest: resumeHash(body), Body: append([]byte(nil), body...), Header: req.Header.Clone()}, nil
}
func resumeSHA(b []byte) []byte { v := sha256.Sum256(b); return v[:] }
func resumeCommitted(events []resumeFixtureTraceEvent, graph, label string, tx uint64) bool {
	for _, e := range events {
		if e.Graph == graph && e.OperationLabel == label && e.TransactionID == tx && e.StatementID == "COMMIT" && e.ReplyKnown {
			return true
		}
	}
	return false
}

type resumeWireRequest struct {
	Kind, Key, VersionID, KeyMarker, VersionIDMarker, BodyDigest, ReservationIdentity, ExpectedBucketOwner string
	PageLimit                                                                                              uint16
	BodyBytes                                                                                              uint32
	MaximumResponse                                                                                        uint32
}

func resumeRequestWire(raw []byte) (resumeWireRequest, error) {
	var v struct {
		Kind                string `json:"kind"`
		Key                 string `json:"key"`
		VersionID           string `json:"version_id"`
		KeyMarker           string `json:"key_marker"`
		VersionIDMarker     string `json:"version_id_marker"`
		BodyDigest          string `json:"body_digest"`
		ReservationIdentity string `json:"reservation_identity"`
		ExpectedBucketOwner string `json:"expected_bucket_owner"`
		PageLimit           uint16 `json:"page_limit"`
		BodyBytes           uint32 `json:"body_bytes"`
		MaximumResponse     uint32 `json:"maximum_response_bytes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return resumeWireRequest{}, err
	}
	return resumeWireRequest{v.Kind, v.Key, v.VersionID, v.KeyMarker, v.VersionIDMarker, v.BodyDigest, v.ReservationIdentity, v.ExpectedBucketOwner, v.PageLimit, v.BodyBytes, v.MaximumResponse}, nil
}
func resumeMatchesWire(r resumeWireRequest, e resumeWireEvent) bool {
	method := "GET"
	query := url.Values{}
	switch r.Kind {
	case "current_read", "intent_read", "attestation_read":
	case "intent_create", "fence_create", "attestation_create":
		method = "PUT"
	case "version_delete":
		method = "DELETE"
		query.Set("versionId", r.VersionID)
	case "version_list":
		query.Set("versions", "")
		query.Set("prefix", r.Key)
		query.Set("max-keys", strconv.Itoa(int(r.PageLimit)))
		if r.KeyMarker != "" {
			query.Set("key-marker", r.KeyMarker)
			query.Set("version-id-marker", r.VersionIDMarker)
		}
	default:
		return false
	}
	digest := resumeHash(nil)
	if method == "PUT" {
		digest = r.BodyDigest
	}
	return (method != "PUT" || uint32(len(e.Body)) == r.BodyBytes) && e.Method == method && e.Key == r.Key && e.Query == strings.ReplaceAll(query.Encode(), "+", "%20") && e.Digest == digest && e.Header.Get("X-Amz-Expected-Bucket-Owner") == r.ExpectedBucketOwner
}
func (p *resumePeer) authorize(e *resumeWireEvent) error {
	p.mu.Lock()
	graph := p.graphs[e.Graph]
	reservedMode := graph != nil && graph.reservedInvocations[e.Invocation]
	p.mu.Unlock()
	if reservedMode && e.Header.Get("X-Amz-Expected-Bucket-Owner") == "" {
		return errors.New("reserved invocation used unbudgeted ordinary backend path")
	}
	snap := p.sql.Snapshot()
	e.SQLSequence = uint64(len(snap.Events))
	p.sql.mu.Lock()
	for _, tx := range p.sql.active {
		if tx.conn.graph == e.Graph {
			p.sql.mu.Unlock()
			return errors.New("remote request inside owning SQL transaction")
		}
	}
	p.sql.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.Header.Get("X-Amz-Expected-Bucket-Owner") != "" {
		for _, event := range snap.Events {
			if event.StatementID != "attempt_insert" || event.Graph != e.Graph || event.OperationLabel != e.Invocation || !resumeCommitted(snap.Events, e.Graph, e.Invocation, event.TransactionID) {
				continue
			}
			r, err := resumeRequestWire(event.Arguments[12].([]byte))
			if err != nil {
				return err
			}
			slot := e.Graph + ":" + r.ReservationIdentity
			if !p.used[slot] && resumeMatchesWire(r, *e) {
				p.used[slot] = true
				e.Attempt = event.Arguments[10].(string)
				e.Transaction = event.TransactionID
				e.MaximumResponse = r.MaximumResponse
				return nil
			}
		}
		return errors.New("wire request has no own known inserted reservation")
	}
	g := p.graphs[e.Graph]
	if g == nil || e.Invocation == "" {
		return errors.New("ordinary graph attribution")
	}
	payload := resumePrefix + "/artifacts/" + g.scope.Identity() + "/" + g.identity
	stem := resumePrefix + "/deletions/" + g.scope.Identity() + "/" + g.identity
	if e.Query != "" || (e.Key != payload && e.Key != stem+".intent" && e.Key != stem+".receipt") || e.Method == "PUT" && e.Key != payload {
		return errors.New("ordinary request key binding")
	}
	for _, event := range snap.Events {
		if event.Graph != e.Graph || event.OperationLabel != e.Invocation || !resumeCommitted(snap.Events, e.Graph, e.Invocation, event.TransactionID) {
			continue
		}
		if e.Method == "PUT" {
			slot := e.Graph + ":" + e.Invocation + ":put"
			if event.StatementID != "admission_insert" || p.used[slot] {
				continue
			}
			p.used[slot] = true
			e.Transaction = event.TransactionID
			return nil
		}
		if e.Method == "GET" && (event.StatementID == "admission_insert" || event.StatementID == "admission_read" || event.StatementID == "operation_read" || event.StatementID == "operation_ref_read") {
			e.Transaction = event.TransactionID
			return nil
		}
	}
	return errors.New("ordinary effect lacks its admission snapshot")
}
func resumeXML(s string) string {
	var out bytes.Buffer
	_ = xml.EscapeText(&out, []byte(s))
	return out.String()
}
func (p *resumePeer) objectReply(e resumeWireEvent, q url.Values) (int, http.Header, []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	headers := http.Header{}
	if owner := e.Header.Get("X-Amz-Expected-Bucket-Owner"); owner != "" && owner != resumeOwner {
		return 403, headers, []byte("<Error><Code>AccessDenied</Code></Error>")
	}
	versions := p.objects[e.Key]
	if q.Has("versions") {
		limit, err := strconv.Atoi(q.Get("max-keys"))
		if err != nil || limit < 1 || limit > 256 {
			return 400, headers, []byte("<Error><Code>InvalidArgument</Code></Error>")
		}
		start := len(versions) - 1
		if marker := q.Get("version-id-marker"); marker != "" {
			start = -1
			for i, v := range versions {
				if v.ID == marker {
					start = i - 1
					break
				}
			}
		}
		end := start - limit + 1
		if end < 0 {
			end = 0
		}
		encode := func(end int) []byte {
			truncated := start >= 0 && end > 0
			var b strings.Builder
			fmt.Fprintf(&b, "<ListVersionsResult><Name>%s</Name><Prefix>%s</Prefix><KeyMarker>%s</KeyMarker><VersionIdMarker>%s</VersionIdMarker><MaxKeys>%d</MaxKeys><IsTruncated>%t</IsTruncated>", resumeBucket, resumeXML(e.Key), resumeXML(q.Get("key-marker")), resumeXML(q.Get("version-id-marker")), limit, truncated)
			for i := start; i >= end && i >= 0; i-- {
				v := versions[i]
				tag := "Version"
				if v.Marker {
					tag = "DeleteMarker"
				}
				fmt.Fprintf(&b, "<%s><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>%s</LastModified>", tag, resumeXML(e.Key), resumeXML(v.ID), i == len(versions)-1, time.Now().UTC().Format(time.RFC3339))
				if !v.Marker {
					fmt.Fprintf(&b, "<ETag>synthetic</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass>", len(v.Body))
				}
				fmt.Fprintf(&b, "</%s>", tag)
			}
			if truncated {
				fmt.Fprintf(&b, "<NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>", resumeXML(e.Key), resumeXML(versions[end].ID))
			}
			b.WriteString("</ListVersionsResult>")
			return []byte(b.String())
		}
		data := encode(end)
		return 200, headers, data
	}
	switch e.Method {
	case "GET":
		if len(versions) == 0 {
			return 404, headers, []byte("<Error><Code>NoSuchKey</Code></Error>")
		}
		v := versions[len(versions)-1]
		headers.Set("X-Amz-Version-Id", v.ID)
		if v.Marker {
			headers.Set("X-Amz-Delete-Marker", "true")
			return 404, headers, []byte("<Error><Code>NoSuchKey</Code></Error>")
		}
		headers.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(resumeSHA(v.Body)))
		if e.Header.Get("X-Amz-Expected-Bucket-Owner") != "" {
			headers.Set("X-Amz-Checksum-Type", "FULL_OBJECT")
		}
		return 200, headers, append([]byte(nil), v.Body...)
	case "PUT":
		if len(versions) > 0 && !versions[len(versions)-1].Marker {
			return 412, headers, nil
		}
		p.nextVersion++
		id := fmt.Sprintf("opaque-%06d", p.nextVersion)
		p.objects[e.Key] = append(versions, resumePeerVersion{id, false, append([]byte(nil), e.Body...)})
		headers.Set("X-Amz-Version-Id", id)
		return 200, headers, nil
	case "DELETE":
		id := q.Get("versionId")
		for i, v := range versions {
			if v.ID == id {
				p.objects[e.Key] = append(versions[:i], versions[i+1:]...)
				headers.Set("X-Amz-Version-Id", id)
				if v.Marker {
					headers.Set("X-Amz-Delete-Marker", "true")
				}
				return 204, headers, nil
			}
		}
		return 404, headers, []byte("<Error><Code>NoSuchVersion</Code></Error>")
	}
	return 405, headers, nil
}

type resumeKMSClient struct {
	peer  *resumePeer
	graph string
}

func (k resumeKMSClient) binding(ctx context.Context, key *string, binding map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k.peer.mu.Lock()
	defer k.peer.mu.Unlock()
	g := k.peer.graphs[k.graph]
	if key == nil || *key != erasureKeyARN || !reflect.DeepEqual(binding, map[string]string{"open_trestle_tenant_binding": resumeHash([]byte("open-trestle/aws-kms-tenant/v1:" + g.scope.TenantID()))}) {
		return errors.New("KMS tenant binding")
	}
	g.kmsCalls++
	if g.kmsCalls > 64 || g.disableKMS || g.reservedInvocations[g.label] {
		k.peer.failures = append(k.peer.failures, "KMS invoked outside admitted payload work")
		return errors.New("KMS prohibited")
	}
	return nil
}
func (k resumeKMSClient) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if err := k.binding(ctx, in.KeyId, in.EncryptionContext); err != nil {
		return nil, err
	}
	if in.KeySpec != types.DataKeySpecAes256 {
		return nil, errors.New("KMS key spec")
	}
	k.peer.mu.Lock()
	g := k.peer.graphs[k.graph]
	label, failure := g.label, g.generateError
	k.peer.mu.Unlock()
	snapshot := k.peer.sql.Snapshot()
	known := false
	for _, e := range snapshot.Events {
		known = known || e.StatementID == "admission_insert" && e.Graph == k.graph && e.OperationLabel == label && resumeCommitted(snapshot.Events, k.graph, label, e.TransactionID)
	}
	if !known {
		return nil, errors.New("KMS before admission insert commit")
	}
	if failure != nil {
		return nil, failure
	}
	key := erasureKeyARN
	return &kms.GenerateDataKeyOutput{KeyId: &key, Plaintext: bytes.Repeat([]byte{0x42}, 32), CiphertextBlob: []byte("synthetic-wrapped-resume-key")}, nil
}
func (k resumeKMSClient) Decrypt(ctx context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if err := k.binding(ctx, in.KeyId, in.EncryptionContext); err != nil {
		return nil, err
	}
	if in.EncryptionAlgorithm != types.EncryptionAlgorithmSpecSymmetricDefault || string(in.CiphertextBlob) != "synthetic-wrapped-resume-key" {
		return nil, errors.New("KMS ciphertext")
	}
	key := erasureKeyARN
	return &kms.DecryptOutput{KeyId: &key, EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault, Plaintext: bytes.Repeat([]byte{0x42}, 32)}, nil
}
func (p *resumePeer) KMSCount(name string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.graphs[name].kmsCalls
}
func (p *resumePeer) DisableKMS(name string) {
	p.mu.Lock()
	p.graphs[name].disableKMS = true
	p.mu.Unlock()
}
func resumeBudgetVector(b artifact.ResumeBudget) []uint64 {
	return []uint64{uint64(b.Requests), uint64(b.Mutations), uint64(b.Reads), uint64(b.Lists), uint64(b.Creates), uint64(b.Deletes), uint64(b.Pages), uint64(b.Versions), b.ResponseBytes, b.ListBytes, b.WriteBytes}
}
func resumeBudgetFrom(v []uint64) artifact.ResumeBudget {
	return artifact.ResumeBudget{Requests: uint32(v[0]), Mutations: uint32(v[1]), Reads: uint32(v[2]), Lists: uint32(v[3]), Creates: uint32(v[4]), Deletes: uint32(v[5]), Pages: uint32(v[6]), Versions: uint32(v[7]), ResponseBytes: v[8], ListBytes: v[9], WriteBytes: v[10]}
}
func resumeMaximum() artifact.ResumeBudget {
	return artifact.ResumeBudget{Requests: 4096, Mutations: 2048, Reads: 2048, Lists: 1024, Creates: 128, Deletes: 2048, Pages: 1024, Versions: 262144, ResponseBytes: 1 << 30, ListBytes: 64 << 20, WriteBytes: 2 << 20}
}
func resumeBudgetJSON(b artifact.ResumeBudget) json.RawMessage {
	v := resumeBudgetVector(b)
	var members []string
	for i, name := range resumeDimensions {
		members = append(members, fmt.Sprintf("%q:%d", name, v[i]))
	}
	return json.RawMessage("{" + strings.Join(members, ",") + "}")
}
func resumeOrdered(t *testing.T, fields map[string]any, order, domain string) []byte {
	return erasureOrdered(t, fields, strings.Fields(order), domain)
}
func resumePolicy(t *testing.T, c erasureCatalog, b *s3.ErasureBackend, now time.Time, changes map[string]any) artifact.ProtectedErasurePolicy {
	t.Helper()
	ns, err := artifact.NewStorageNamespace(b.ConfigurationIdentity(), resumePrefix, strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	db, _ := json.Marshal(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Database  string `json:"database"`
		Schema    string `json:"schema"`
		Role      string `json:"role"`
		Namespace string `json:"namespace"`
	}{"open-trestle/postgresql-database-authority", 1, c.Database, c.Schema, c.Role, c.Namespace})
	fields := map[string]any{"contract": "open-trestle/protected-artifact-erasure-policy", "schema_version": 1, "namespace_identity": ns.Identity(), "backend_configuration_identity": b.ConfigurationIdentity(), "prefix": resumePrefix, "namespace_epoch_identity": strings.Repeat("2", 64), "backend_kind": "aws_s3_general_purpose", "database_authority_identity": resumeHash(db), "namespace_mode": "protected_new_nonnull", "protocol": "same-key-fence-v2", "ownership": "all_versions_at_exact_key", "fence_retention_policy_identity": strings.Repeat("4", 64), "erasure_policy_identity": strings.Repeat("5", 64), "recovery_policy_identity": strings.Repeat("6", 64), "configuration_evidence_identity": strings.Repeat("7", 64), "not_before_milliseconds": now.Add(-time.Minute).UnixMilli(), "not_after_milliseconds": now.Add(10 * time.Minute).UnixMilli()}
	for key, v := range changes {
		fields[key] = v
	}
	raw := resumeOrdered(t, fields, strings.Join(erasurePolicyOrder, " "), "open-trestle/protected-artifact-erasure-policy/v1\x00")
	p, err := artifact.LoadProtectedErasurePolicy(context.Background(), erasureProtectedFile(t, raw))
	if err != nil {
		t.Fatal("protected policy", err)
	}
	return p
}
func resumeGrant(t *testing.T, p artifact.ProtectedErasurePolicy, a artifact.ArtifactAdmission, now time.Time, expires ...time.Time) artifact.ErasureAuthorizationV2 {
	t.Helper()
	s := a.Scope()
	fields := map[string]any{"contract": "open-trestle/artifact-erasure-authorization", "schema_version": 2, "namespace_identity": a.NamespaceIdentity(), "scope_identity": s.Identity(), "tenant_id": s.TenantID(), "repository_id": s.RepositoryID(), "review_run_id": s.ReviewRunID(), "artifact_identity": a.ArtifactIdentity(), "admission_identity": a.Identity(), "policy_identity": p.ErasurePolicyIdentity(), "principal_identity": strings.Repeat("8", 64), "hold_clearance_identity": strings.Repeat("9", 64), "ownership": "all_versions_at_exact_key", "fence_retention_policy_identity": p.FenceRetentionPolicyIdentity(), "reason": "tenant_erasure", "issued_at_milliseconds": now.Add(-time.Second).UnixMilli(), "expires_at_milliseconds": now.Add(5 * time.Minute).UnixMilli(), "legacy_receipt_identity": ""}
	if len(expires) > 0 {
		fields["expires_at_milliseconds"] = expires[0].UnixMilli()
	}
	raw := resumeOrdered(t, fields, "contract schema_version identity namespace_identity scope_identity tenant_id repository_id review_run_id artifact_identity admission_identity policy_identity principal_identity hold_clearance_identity ownership fence_retention_policy_identity reason issued_at_milliseconds expires_at_milliseconds legacy_receipt_identity", "open-trestle/artifact-erasure-authorization/v2\x00")
	g, err := artifact.LoadErasureAuthorizationV2(context.Background(), erasureProtectedFile(t, raw), p)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func resumeAllowance(t *testing.T, p artifact.ProtectedErasurePolicy, op artifact.ErasureOperation, at time.Time, issuance string, max artifact.ResumeBudget, owner ...string) (artifact.ResumeAllowance, string, []byte) {
	t.Helper()
	fields := map[string]any{"contract": "open-trestle/artifact-erasure-resume-allowance", "schema_version": 1, "namespace_identity": op.NamespaceIdentity(), "scope_identity": op.Scope().Identity(), "artifact_identity": op.ArtifactIdentity(), "admission_identity": op.AdmissionIdentity(), "operation_identity": op.Identity(), "original_authorization_identity": op.OriginalAuthorizationIdentity(), "authorization_document_digest": op.AuthorizationDocumentDigest(), "recovery_policy_identity": p.RecoveryPolicyIdentity(), "protected_policy_identity": p.Identity(), "principal_identity": strings.Repeat("8", 64), "issuance_identity": resumeHash([]byte(issuance)), "expected_bucket_owner": resumeOwner, "not_before_milliseconds": at.UnixMilli(), "not_after_milliseconds": at.Add(5 * time.Minute).UnixMilli(), "maximum": resumeBudgetJSON(max)}
	if len(owner) > 0 {
		fields["expected_bucket_owner"] = owner[0]
	}
	raw := resumeOrdered(t, fields, "contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity operation_identity original_authorization_identity authorization_document_digest recovery_policy_identity protected_policy_identity principal_identity issuance_identity expected_bucket_owner not_before_milliseconds not_after_milliseconds maximum", "open-trestle/artifact-erasure-resume-allowance/v1\x00")
	path := erasureProtectedFile(t, raw)
	a, err := artifact.LoadResumeAllowance(context.Background(), path, p, op.Scope())
	if err != nil {
		t.Fatal(err)
	}
	if a.ProtectedDocumentDigest() != resumeHash(raw) {
		t.Fatal("allowance document digest")
	}
	return a, path, raw
}

type resumeJournalGraph struct {
	t       *testing.T
	sql     *resumeFixtureSQLService
	peer    *resumePeer
	db      *sql.DB
	index   *ArtifactIndex
	witness VerifiedBudgetedErasureIndex
	backend *s3.ErasureBackend
	keys    *awskms.Provider
	clock   *resumeClock
	policy  artifact.ProtectedErasurePolicy
	journal *artifactResumeJournal
	store   *artifact.EnvelopeStore
	scope   audit.ReviewScope
	value   artifact.Artifact
	name    string
}

func newResumeJournalGraph(t *testing.T, s *resumeFixtureSQLService, p *resumePeer, value artifact.Artifact, policy artifact.ProtectedErasurePolicy, at time.Time, name string) *resumeJournalGraph {
	t.Helper()
	g := &resumeJournalGraph{t: t, sql: s, peer: p, scope: value.Scope(), value: value, name: name}
	g.clock = &resumeClock{at: at, sql: s, graph: name}
	g.backend = p.backend(t, name, g.scope, value.Identity())
	g.policy = policy
	if g.policy.Validate() != nil {
		g.policy = resumePolicy(t, s.catalog, g.backend, at, nil)
	}
	var err error
	g.keys, err = awskms.New(resumeKMSClient{p, name}, resumeRegion, []awskms.TenantKey{{TenantID: g.scope.TenantID(), KeyARN: erasureKeyARN}})
	if err != nil {
		t.Fatal(err)
	}
	g.db = s.OpenDB(t, name)
	g.index, err = NewArtifactIndex(g.db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := g.Context("verify")
	g.witness, err = VerifyBudgetedErasureIndex(ctx, g.index)
	if err != nil {
		t.Fatal("budgeted schema", err)
	}
	sqlBefore, wireBefore, samples := len(s.Snapshot().Events), len(p.Events()), g.clock.Samples()
	g.journal, err = newArtifactResumeJournal(g.index, g.witness, g.policy, g.clock)
	if err != nil {
		t.Fatal(err)
	}
	g.store, err = artifact.NewEnvelopeStoreWithAdmissionPreparation(artifact.EnvelopeAdmissionPreparationOptions{Backend: g.backend, Keys: g.keys, Journal: g.journal, Policy: g.policy, Clock: g.clock})
	if err != nil {
		t.Fatal(err)
	}
	if sqlBefore != len(s.Snapshot().Events) || wireBefore != len(p.Events()) || samples != g.clock.Samples() || p.KMSCount(name) != 0 {
		t.Fatal("constructor performed I/O or sampled time")
	}
	return g
}
func (g *resumeJournalGraph) Context(label string) context.Context {
	g.peer.mu.Lock()
	g.peer.graphs[g.name].label = label
	g.peer.mu.Unlock()
	ctx, cancel := resumeFixtureOperationContext(g.t, label)
	g.t.Cleanup(cancel)
	return ctx
}
func (g *resumeJournalGraph) Key() artifact.ExactObjectKey {
	k, err := artifact.NewExactObjectKey(g.policy.NamespaceIdentity(), resumePrefix+"/artifacts/"+g.scope.Identity()+"/"+g.value.Identity())
	if err != nil {
		g.t.Fatal(err)
	}
	return k
}
func (g *resumeJournalGraph) Prepared() (artifact.ArtifactAdmission, artifact.ErasureOperation, artifact.ErasureAuthorizationV2) {
	g.t.Helper()
	ctx := g.Context("put")
	ok, err := g.store.Put(ctx, g.value, g.clock.Value())
	if err != nil || !ok {
		g.t.Fatal("real admitted Put", err)
	}
	ctx = g.Context("get")
	got, err := g.store.Get(ctx, g.scope, g.value.Identity(), g.clock.Value())
	if err != nil || !bytes.Equal(got.Payload(), g.value.Payload()) {
		g.t.Fatal("real Get", err)
	}
	a, found, err := g.store.ReadAdmission(g.Context("admission"), g.scope, g.policy.NamespaceIdentity(), g.value.Identity())
	if err != nil || !found {
		g.t.Fatal(err)
	}
	grant := resumeGrant(g.t, g.policy, a, g.clock.Value())
	before := len(g.peer.Events())
	kms := g.peer.KMSCount(g.name)
	op, err := g.store.PrepareErasure(g.Context("prepare"), grant, g.clock.Value())
	if err != nil {
		g.t.Fatal(err)
	}
	if len(g.peer.Events()) != before || g.peer.KMSCount(g.name) != kms {
		g.t.Fatal("Prepare performed remote work")
	}
	if _, err := g.store.Get(g.Context("deleted-get"), g.scope, g.value.Identity(), g.clock.Value()); !errors.Is(err, artifact.ErrArtifactDeleted) {
		g.t.Fatal("Get after preparation", err)
	}
	g.peer.DisableKMS(g.name)
	return a, op, grant
}
func newResumeJournalFixture(t *testing.T) *resumeJournalGraph {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Millisecond)
	scope, err := audit.NewReviewScope("tenant-resume", "repo-resume", "run-resume")
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindContextPacket, "text/plain", artifact.ClassificationRestricted, artifact.OriginMemory, artifact.ProtectionEnvelopeEncrypted, []string{strings.Repeat("a", 64)}, []byte("synthetic resume payload"), at.Add(-time.Minute), at.Add(20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	s := newResumeSQLService(t, newResumeCatalog(t))
	p := newResumePeer(t, s)
	return newResumeJournalGraph(t, s, p, value, artifact.ProtectedErasurePolicy{}, at, "first")
}
func resumeExpectedAttempt(t *testing.T, r artifact.AttemptRequest, sequence uint64, at time.Time) []byte {
	return resumeOrdered(t, map[string]any{"contract": "open-trestle/artifact-erasure-attempt", "schema_version": 1, "request_identity": r.Identity(), "sequence": sequence, "reserved_at_milliseconds": at.UnixMilli()}, "contract schema_version identity request_identity sequence reserved_at_milliseconds", "open-trestle/artifact-erasure-attempt/v1\x00")
}
func resumeExpectedUnknown(t *testing.T, a artifact.ErasureAttempt, at time.Time) []byte {
	r := a.Request()
	return resumeOrdered(t, map[string]any{"contract": "open-trestle/artifact-erasure-evidence", "schema_version": 1, "namespace_identity": r.NamespaceIdentity(), "scope_identity": r.ScopeIdentity(), "operation_identity": r.OperationIdentity(), "kind": "unknown", "slot": "unknown:" + a.Identity(), "attempt_identity": a.Identity(), "observed_at_milliseconds": at.UnixMilli(), "parent_identities": []string{}, "record_hex": ""}, "contract schema_version identity namespace_identity scope_identity operation_identity kind slot attempt_identity observed_at_milliseconds parent_identities record_hex", "open-trestle/artifact-erasure-evidence/v1\x00")
}
func resumeCost(r artifact.AttemptRequest) artifact.ResumeBudget {
	v := artifact.ResumeBudget{Requests: 1, ResponseBytes: uint64(r.MaximumResponseBytes()) + 1}
	switch r.Kind() {
	case artifact.AttemptCurrentRead, artifact.AttemptIntentRead, artifact.AttemptAttestationRead:
		v.Reads = 1
	case artifact.AttemptVersionList:
		v.Lists = 1
		v.Pages = 1
		v.Versions = uint32(r.PageLimit())
		v.ListBytes = v.ResponseBytes
	case artifact.AttemptVersionDelete:
		v.Mutations = 1
		v.Deletes = 1
	case artifact.AttemptIntentCreate, artifact.AttemptFenceCreate, artifact.AttemptAttestationCreate:
		v.Mutations = 1
		v.Creates = 1
		v.WriteBytes = uint64(r.BodyBytes())
	}
	return v
}
func resumeCurrentRequest(t *testing.T, g *resumeJournalGraph, op artifact.ErasureOperation, a artifact.ResumeAllowance, label string) artifact.AttemptRequest {
	t.Helper()
	r, err := artifact.NewAttemptRequest(artifact.AttemptRequestOptions{ReservationIdentity: resumeHash([]byte(label)), Operation: op, Allowance: a, Kind: artifact.AttemptCurrentRead, Key: g.Key(), MaximumResponseBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func resumeAssertAttempt(t *testing.T, a artifact.ErasureAttempt, r artifact.AttemptRequest, sequence uint64, at time.Time) {
	t.Helper()
	requestBytes, requestErr := artifact.EncodeAttemptRequest(a.Request())
	if requestErr != nil || !bytes.Equal(requestBytes, resumeExpectedRequest(t, r)) {
		t.Fatal("canonical request output", requestErr)
	}
	raw, err := artifact.EncodeErasureAttempt(a)
	if err != nil || !bytes.Equal(raw, resumeExpectedAttempt(t, r, sequence, at)) {
		t.Fatal("canonical reserved attempt", err)
	}
}

var _ artifact.ResumeJournal = (*artifactResumeJournal)(nil)

func resumeFenceBytes(t *testing.T, op artifact.ErasureOperation) []byte {
	fields := map[string]any{"contract": "open-trestle/artifact-erasure-fence", "schema_version": 1, "erasure_protocol": "same-key-fence-v2", "namespace_identity": op.NamespaceIdentity(), "scope_identity": op.Scope().Identity(), "artifact_identity": op.ArtifactIdentity(), "operation_identity": op.Identity(), "prepared_at_milliseconds": op.PreparedAt().UnixMilli()}
	return append([]byte("OTAF0001"), resumeOrdered(t, fields, "contract schema_version identity erasure_protocol namespace_identity scope_identity artifact_identity operation_identity prepared_at_milliseconds", "open-trestle/artifact-erasure-fence/v1\x00")...)
}
func resumeJournalReserve(t *testing.T, g *resumeJournalGraph, op artifact.ErasureOperation, a artifact.ResumeAllowance, options artifact.AttemptRequestOptions, label string) artifact.ErasureAttempt {
	t.Helper()
	options.Operation = op
	options.Allowance = a
	options.ReservationIdentity = resumeHash([]byte(label))
	request, err := artifact.NewAttemptRequest(options)
	if err != nil {
		t.Fatal(err)
	}
	attempt, inserted, err := g.journal.ReserveErasureAttempt(g.Context(label), op.Ref(), a, request, g.clock.Value())
	if err != nil || !inserted {
		t.Fatal("journal reservation", err)
	}
	rows := g.sql.Snapshot().Rows[resumeAttempts]
	for _, row := range rows {
		if row["attempt_identity"] == attempt.Identity() {
			if !bytes.Equal(row["canonical_request"].([]byte), resumeExpectedRequest(t, request)) {
				t.Fatal("canonical request differs from independent fields/hash")
			}
			expected := resumeBudgetVector(resumeCost(request))
			for i, name := range resumeDimensions {
				if row["cost_"+name] != int64(expected[i]) {
					t.Fatal("independent reservation cost", name)
				}
			}
		}
	}
	return attempt
}
func resumeJournalRecord(t *testing.T, g *resumeJournalGraph, op artifact.ErasureOperation, e artifact.ErasureEvidence) artifact.ErasureEvidence {
	t.Helper()
	got, _, err := g.journal.RecordErasureEvidence(g.Context("record-"+e.Identity()), op.Ref(), e)
	if err != nil {
		t.Fatal("journal evidence", err)
	}
	return got
}
func resumeJournalRead(t *testing.T, g *resumeJournalGraph, op artifact.ErasureOperation, a artifact.ResumeAllowance, kind artifact.AttemptKind, key artifact.ExactObjectKey, label string) (artifact.ErasureAttempt, artifact.ErasureEvidence) {
	t.Helper()
	attempt := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: kind, Key: key, MaximumResponseBytes: 16384}, label)
	observed, err := g.backend.ReadErasureObject(g.Context(label), key, resumeOwner, 16384)
	if err != nil {
		t.Fatal("owned read", err)
	}
	options := artifact.AttemptResponseOptions{Attempt: attempt, ObservedAt: g.clock.Value(), Code: artifact.AttemptResponseAbsent}
	switch observed.Kind {
	case artifact.ErasureReadPresent:
		options.Code = artifact.AttemptResponsePresent
		options.ContentDigest = observed.Object.Digest
		options.ResponseBytes = uint32(len(observed.Object.Content))
		options.Version, err = artifact.NewObjectVersion(key.NamespaceIdentity(), key.Key(), artifact.ObjectVersionData, strings.TrimPrefix(observed.Object.Version, "version:"))
		if err != nil {
			t.Fatal(err)
		}
		switch kind {
		case artifact.AttemptCurrentRead:
			options.ContentKind = "ciphertext"
			if bytes.Equal(observed.Object.Content, resumeFenceBytes(t, op)) {
				options.ContentKind = "fence"
				options.CanonicalRecord = observed.Object.Content
			}
		case artifact.AttemptIntentRead:
			options.ContentKind = "operation"
			options.CanonicalRecord = observed.Object.Content
		case artifact.AttemptAttestationRead:
			options.ContentKind = "attestation"
			options.CanonicalRecord = observed.Object.Content
		}
	case artifact.ErasureReadCurrentDeleteMarker:
		options.ContentKind = "delete_marker"
		options.Version = observed.Marker
	case artifact.ErasureReadAbsent:
	default:
		t.Fatal("read kind")
	}
	evidence, err := artifact.NewAttemptResponseEvidence(options)
	if err != nil {
		t.Fatal(err)
	}
	return attempt, resumeJournalRecord(t, g, op, evidence)
}
func resumeJournalCreate(t *testing.T, g *resumeJournalGraph, op artifact.ErasureOperation, a artifact.ResumeAllowance, kind artifact.AttemptKind, key artifact.ExactObjectKey, body []byte, observation artifact.ErasureEvidence, label string) artifact.ErasureEvidence {
	t.Helper()
	attempt := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: kind, Key: key, MaximumResponseBytes: 4096, BodyBytes: uint32(len(body)), BodyDigest: resumeHash(body), ObservationIdentity: observation.Identity()}, label)
	created, err := g.backend.CreateErasureObject(g.Context(label), key, resumeOwner, body, resumeHash(body))
	if err != nil {
		t.Fatal("owned conditional create", err)
	}
	code := artifact.AttemptResponseConditionLost
	if created {
		code = artifact.AttemptResponseCreated
	}
	response, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: code, ObservedAt: g.clock.Value()})
	if err != nil {
		t.Fatal(err)
	}
	return resumeJournalRecord(t, g, op, response)
}
func resumeJournalList(t *testing.T, g *resumeJournalGraph, op artifact.ErasureOperation, a artifact.ResumeAllowance, label string, limit uint16, cursor artifact.VersionCursor) (artifact.ErasureAttempt, artifact.ErasureEvidence) {
	t.Helper()
	attempt := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionList, Key: g.Key(), Cursor: cursor, PageLimit: limit, MaximumResponseBytes: 65536}, label)
	page, err := g.backend.ListObjectVersions(g.Context(label), g.Key(), resumeOwner, cursor, limit, 65536)
	if err != nil {
		t.Fatal(err)
	}
	response, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: artifact.AttemptResponsePresent, ObservedAt: g.clock.Value(), Page: page, ResponseBytes: page.ResponseBytes})
	if err != nil {
		t.Fatal(err)
	}
	return attempt, resumeJournalRecord(t, g, op, response)
}

func TestResumeExternalReservationOracleCalibration(t *testing.T) {
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "oracle", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	request := resumeCurrentRequest(t, g, op, a, "oracle-reservation")
	attempt, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, request, g.clock.Value())
	if err != nil || !inserted {
		t.Fatal(err)
	}
	event := resumeWireEvent{Graph: g.name, Invocation: "reserve", Method: "GET", Key: g.Key().Key(), Digest: resumeHash(nil), Header: http.Header{"X-Amz-Expected-Bucket-Owner": []string{resumeOwner}}}
	for _, mode := range []string{"matching", "missing insert", "other graph commit", "other invocation commit", "persisted but reply lost", "wrong key", "wrong body", "duplicate use"} {
		t.Run(mode, func(t *testing.T) {
			trace := append([]resumeFixtureTraceEvent(nil), g.sql.Snapshot().Events...)
			wire := event
			switch mode {
			case "missing insert":
				for i := range trace {
					if trace[i].StatementID == "attempt_insert" {
						trace[i].StatementID = "attempt_read"
					}
				}
			case "other graph commit":
				for i := range trace {
					if trace[i].StatementID == "COMMIT" {
						trace[i].Graph = "other"
					}
				}
			case "other invocation commit":
				for i := range trace {
					if trace[i].StatementID == "COMMIT" {
						trace[i].OperationLabel = "other"
					}
				}
			case "persisted but reply lost":
				for i := range trace {
					if trace[i].StatementID == "COMMIT" {
						trace[i].ReplyKnown = false
					}
				}
			case "wrong key":
				wire.Key += ".wrong"
			case "wrong body":
				wire.Digest = resumeHash([]byte("not the reserved body"))
			}
			observer := &resumePeer{sql: &resumeFixtureSQLService{events: trace, active: map[uint64]*resumeFixtureTransaction{}}, used: map[string]bool{}}
			err := observer.authorize(&wire)
			valid := mode == "matching" || mode == "duplicate use"
			if valid {
				if err != nil || wire.Attempt != attempt.Identity() {
					t.Fatal("matching reservation refused", err)
				}
			} else if err == nil {
				t.Fatal("unrelated observation authorized effect")
			}
			if mode == "duplicate use" {
				second := event
				if err := observer.authorize(&second); err == nil {
					t.Fatal("same reservation authorized two effects")
				}
			}
		})
	}
}

func resumeExpectedRequest(t *testing.T, r artifact.AttemptRequest) []byte {
	kind := ""
	if r.VersionKind() == artifact.ObjectVersionData {
		kind = "data"
	}
	if r.VersionKind() == artifact.ObjectVersionDeleteMarker {
		kind = "delete_marker"
	}
	fields := map[string]any{"contract": "open-trestle/artifact-erasure-attempt-request", "schema_version": 1, "reservation_identity": r.ReservationIdentity(), "namespace_identity": r.NamespaceIdentity(), "scope_identity": r.ScopeIdentity(), "artifact_identity": r.ArtifactIdentity(), "admission_identity": r.AdmissionIdentity(), "operation_identity": r.OperationIdentity(), "original_authorization_identity": r.OriginalAuthorizationIdentity(), "authorization_document_digest": r.AuthorizationDocumentDigest(), "allowance_identity": r.AllowanceIdentity(), "allowance_document_digest": r.AllowanceDocumentDigest(), "protected_policy_identity": r.ProtectedPolicyIdentity(), "expected_bucket_owner": r.ExpectedBucketOwner(), "kind": r.Kind().String(), "key": r.Key(), "version_kind": kind, "version_id": r.VersionID(), "key_marker": r.KeyMarker(), "version_id_marker": r.VersionIDMarker(), "page_limit": r.PageLimit(), "maximum_response_bytes": r.MaximumResponseBytes(), "body_digest": r.BodyDigest(), "body_bytes": r.BodyBytes(), "condition": r.Condition(), "observation_identity": r.ObservationIdentity()}
	return resumeOrdered(t, fields, "contract schema_version identity reservation_identity namespace_identity scope_identity artifact_identity admission_identity operation_identity original_authorization_identity authorization_document_digest allowance_identity allowance_document_digest protected_policy_identity expected_bucket_owner kind key version_kind version_id key_marker version_id_marker page_limit maximum_response_bytes body_digest body_bytes condition observation_identity", "open-trestle/artifact-erasure-attempt-request/v1\x00")
}
func resumeOperationBytes(t *testing.T, op artifact.ErasureOperation) []byte {
	return resumeOrdered(t, map[string]any{"contract": "open-trestle/artifact-erasure-operation", "schema_version": 2, "namespace_identity": op.NamespaceIdentity(), "scope_identity": op.Scope().Identity(), "artifact_identity": op.ArtifactIdentity(), "admission_identity": op.AdmissionIdentity(), "original_authorization_identity": op.OriginalAuthorizationIdentity(), "authorization_document_digest": op.AuthorizationDocumentDigest(), "policy_identity": op.PolicyIdentity(), "protected_policy_identity": op.ProtectedPolicyIdentity(), "ownership": op.Ownership(), "prepared_at_milliseconds": op.PreparedAt().UnixMilli(), "erasure_protocol": op.ErasureProtocol(), "legacy_receipt_identity": op.LegacyReceiptIdentity()}, "contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity original_authorization_identity authorization_document_digest policy_identity protected_policy_identity ownership prepared_at_milliseconds erasure_protocol legacy_receipt_identity", "open-trestle/artifact-erasure-operation/v2\x00")
}

func (p *resumePeer) AddOpaqueHistory(t *testing.T, key, id string, marker bool, body []byte) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.objects[key]) == 0 || len(id) == 0 || len(id) > 504 {
		t.Fatal("opaque history requires prior actual object and bounded token")
	}
	for _, v := range p.objects[key] {
		if v.ID == id {
			t.Fatal("duplicate external version")
		}
	}
	p.objects[key] = append(p.objects[key], resumePeerVersion{id, marker, append([]byte(nil), body...)})
}
func resumeIndependentResponse(t *testing.T, op artifact.ErasureOperation, attempt artifact.ErasureAttempt, page artifact.VersionPage, at time.Time) []byte {
	t.Helper()
	type entry struct {
		Identity string `json:"version_identity"`
		Kind     string `json:"kind"`
		Version  string `json:"version_id"`
		Latest   bool   `json:"is_latest"`
	}
	entries := make([]entry, 0, len(page.Entries))
	for _, e := range page.Entries {
		kind := "data"
		if e.Version.Kind() == artifact.ObjectVersionDeleteMarker {
			kind = "delete_marker"
		}
		fields := map[string]any{"contract": "open-trestle/artifact-object-version", "schema_version": 1, "namespace_identity": op.NamespaceIdentity(), "key": e.Version.Key(), "kind": kind, "version_id": e.Version.VersionID()}
		resumeOrdered(t, fields, "contract schema_version identity namespace_identity key kind version_id", "open-trestle/artifact-object-version/v1\x00")
		if e.Version.Identity() != fields["identity"].(string) {
			t.Fatal("version hash independent oracle")
		}
		entries = append(entries, entry{fields["identity"].(string), kind, e.Version.VersionID(), e.IsLatest})
	}
	fields := map[string]any{"contract": "open-trestle/artifact-erasure-response", "schema_version": 1, "operation_identity": op.Identity(), "attempt_identity": attempt.Identity(), "observed_at_milliseconds": at.UnixMilli(), "code": "present", "content_kind": "", "version_kind": "", "version_id": "", "content_digest": "", "record_hex": "", "response_bytes": page.ResponseBytes, "entries": entries, "key_marker": page.Next.KeyMarker, "version_id_marker": page.Next.VersionIDMarker, "truncated": page.Truncated}
	return resumeOrdered(t, fields, "contract schema_version identity operation_identity attempt_identity observed_at_milliseconds code content_kind version_kind version_id content_digest record_hex response_bytes entries key_marker version_id_marker truncated", "open-trestle/artifact-erasure-response/v1\x00")
}

func resumePageFromWire(t *testing.T, key artifact.ExactObjectKey, raw []byte) artifact.VersionPage {
	t.Helper()
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	page := artifact.VersionPage{ResponseBytes: uint32(len(raw))}
	scalars := map[string]string{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("independent XML decoder", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local == "ListVersionsResult" {
			continue
		}
		if start.Name.Local == "Version" || start.Name.Local == "DeleteMarker" {
			var item struct {
				Key     string `xml:"Key"`
				Version string `xml:"VersionId"`
				Latest  bool   `xml:"IsLatest"`
			}
			if err := decoder.DecodeElement(&item, &start); err != nil {
				t.Fatal(err)
			}
			if item.Key != key.Key() {
				t.Fatal("external XML wrong key")
			}
			kind := artifact.ObjectVersionData
			if start.Name.Local == "DeleteMarker" {
				kind = artifact.ObjectVersionDeleteMarker
			}
			version, err := artifact.NewObjectVersion(key.NamespaceIdentity(), item.Key, kind, item.Version)
			if err != nil {
				t.Fatal(err)
			}
			page.Entries = append(page.Entries, artifact.VersionEntry{Version: version, IsLatest: item.Latest})
			continue
		}
		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			t.Fatal(err)
		}
		if _, ok := scalars[start.Name.Local]; ok {
			t.Fatal("duplicate external XML scalar")
		}
		scalars[start.Name.Local] = value
	}
	if scalars["Name"] != resumeBucket || scalars["Prefix"] != key.Key() {
		t.Fatal("external XML binding")
	}
	page.Truncated = scalars["IsTruncated"] == "true"
	page.Next = artifact.VersionCursor{KeyMarker: scalars["NextKeyMarker"], VersionIDMarker: scalars["NextVersionIdMarker"]}
	return page
}
func resumeEvidenceInner(t *testing.T, raw []byte) []byte {
	t.Helper()
	var outer struct {
		Record string `json:"record_hex"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	inner, err := hex.DecodeString(outer.Record)
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

type resumeWorkers struct {
	mu      sync.Mutex
	cancels []context.CancelFunc
	done    []<-chan struct{}
}

func newResumeWorkers(t *testing.T) *resumeWorkers {
	t.Helper()
	w := &resumeWorkers{}
	t.Cleanup(func() {
		w.mu.Lock()
		cancels := append([]context.CancelFunc(nil), w.cancels...)
		done := append([]<-chan struct{}(nil), w.done...)
		w.mu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		timer := time.NewTimer(6 * time.Second)
		defer timer.Stop()
		for _, joined := range done {
			select {
			case <-joined:
			case <-timer.C:
				t.Error("test worker failed to join after cancellation")
				return
			}
		}
	})
	return w
}
func (w *resumeWorkers) Start(ctx context.Context, work func(context.Context)) {
	owned, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	w.mu.Lock()
	w.cancels = append(w.cancels, cancel)
	w.done = append(w.done, done)
	w.mu.Unlock()
	go func() { defer close(done); work(owned) }()
}

func resumeJournalFenceInput(t *testing.T) (*resumeJournalGraph, artifact.ArtifactAdmission, artifact.ErasureOperation, artifact.ResumeAllowance, artifact.ErasureEvidence) {
	t.Helper()
	g := newResumeJournalFixture(t)
	admission, op, _ := g.Prepared()
	allowance, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "terminal-input", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), allowance, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	attempt, response := resumeJournalRead(t, g, op, allowance, artifact.AttemptCurrentRead, g.Key(), "current-ciphertext")
	observed, err := artifact.ParseAttemptResponseEvidence(response, attempt)
	if err != nil {
		t.Fatal(err)
	}
	deletion := resumeJournalReserve(t, g, op, allowance, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionDelete, Key: g.Key(), Version: observed.Version, ObservationIdentity: response.Identity(), MaximumResponseBytes: 4096}, "vacate")
	outcome, err := g.backend.DeleteObjectVersion(g.Context("vacate"), g.Key(), resumeOwner, observed.Version)
	if err != nil || outcome != artifact.VersionDeleteDeleted {
		t.Fatal(err)
	}
	deleted, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: deletion, Code: artifact.AttemptResponseDeleted, ObservedAt: g.clock.Value()})
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, deleted)
	_, absent := resumeJournalRead(t, g, op, allowance, artifact.AttemptCurrentRead, g.Key(), "absence")
	resumeJournalCreate(t, g, op, allowance, artifact.AttemptFenceCreate, g.Key(), resumeFenceBytes(t, op), absent, "create-fence")
	_, current := resumeJournalRead(t, g, op, allowance, artifact.AttemptCurrentRead, g.Key(), "observe-fence")
	return g, admission, op, allowance, current
}
