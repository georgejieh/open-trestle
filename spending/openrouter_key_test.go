package spending

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// A synthetic, offline stand-in for OpenRouter's GET /api/v1/key. The shape
// follows OpenRouter's documented report; every value is made up. Nothing
// here contacts OpenRouter.

const testOpenRouterKey = "sk-or-v1-synthetic-test-key-0000000000000000"

type fakeKeyAPI struct {
	mu       sync.Mutex
	status   int
	body     string
	header   http.Header
	requests []*http.Request
}

func (f *fakeKeyAPI) RoundTrip(request *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, request)
	f.mu.Unlock()
	header := f.header
	if header == nil {
		header = http.Header{"Content-Type": []string{"application/json"}}
	}
	return &http.Response{StatusCode: f.status, Header: header, Body: io.NopCloser(strings.NewReader(f.body)), Request: request}, nil
}

// keyReport is a report with a masked key label, like OpenRouter's.
func keyReport(fields string) string {
	return `{"data":{"label":"sk-or-v1-abc...789","is_free_tier":false,"is_provisioning_key":false,"include_byok_in_limit":false,"byok_usage":0,"rate_limit":{"requests":-1,"interval":"10s"},` + fields + `}}`
}

const monthlyFields = `"limit":50,"limit_remaining":49.921,"limit_reset":"monthly","usage":0.079,"usage_daily":0.01,"usage_weekly":0.02,"usage_monthly":0.079`

func TestOpenRouterKeyUsageReadsOnlyTheBoundedNumbers(t *testing.T) {
	fake := &fakeKeyAPI{status: http.StatusOK, body: keyReport(monthlyFields)}
	usage, err := ReadOpenRouterKeyUsage(context.Background(), fake, testOpenRouterKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.requests) != 1 {
		t.Fatalf("requests=%d, want one", len(fake.requests))
	}
	request := fake.requests[0]
	if request.Method != http.MethodGet || request.URL.String() != OpenRouterKeyURL || request.Header.Get("Authorization") != "Bearer "+testOpenRouterKey || request.Body != nil && request.Body != http.NoBody {
		t.Fatalf("the read was not one GET of %s with the bearer key: %s %s", OpenRouterKeyURL, request.Method, request.URL)
	}
	want := OpenRouterKeyUsage{HasLimit: true, LimitMicroUSD: 50_000_000, HasLimitRemaining: true, LimitRemainingMicroUSD: 49_921_000, LimitReset: "monthly", UsageMicroUSD: 79_000, DailyMicroUSD: 10_000, WeeklyMicroUSD: 20_000, MonthlyMicroUSD: 79_000}
	if usage != want {
		t.Fatalf("usage=%+v\nwant %+v", usage, want)
	}
	if line := usage.Line(); line != "OpenRouter reports $0.08 used this month of this key's $50.00 monthly limit" {
		t.Fatalf("line: %s", line)
	}
	if shown := fmt.Sprintf("%+v %s", usage, usage.Line()); strings.Contains(shown, "sk-or") || strings.Contains(shown, "abc") {
		t.Fatalf("the label reached the result: %s", shown)
	}
	for _, test := range []struct{ fields, line string }{
		{`"limit":null,"limit_remaining":null,"limit_reset":null,"usage":1.5,"usage_daily":0,"usage_weekly":0,"usage_monthly":0.5`, "OpenRouter reports $0.50 used this month; this key has no OpenRouter limit (set one in OpenRouter's key settings for a hard cap)"},
		{`"limit":20,"limit_remaining":18.5,"limit_reset":null,"usage":1.5,"usage_daily":0,"usage_weekly":0,"usage_monthly":0.5`, "OpenRouter reports $1.50 used in total of this key's $20.00 limit"},
		{`"limit":5,"limit_remaining":4,"limit_reset":"weekly","usage":9,"usage_daily":0.25,"usage_weekly":1,"usage_monthly":3`, "OpenRouter reports $1.00 used this week of this key's $5.00 weekly limit"},
		{`"limit":1,"limit_remaining":1,"limit_reset":"daily","usage":9,"usage_daily":7.9e-05,"usage_weekly":1,"usage_monthly":3`, "OpenRouter reports $0.01 used today of this key's $1.00 daily limit"},
		{`"limit":5,"limit_remaining":4,"limit_reset":"yearly","usage":9,"usage_daily":0,"usage_weekly":1,"usage_monthly":3`, "OpenRouter reports $9.00 used in total of this key's $5.00 limit (reset: yearly)"},
	} {
		parsed, err := ParseOpenRouterKeyUsage([]byte(keyReport(test.fields)))
		if err != nil || parsed.Line() != test.line {
			t.Errorf("%s: %v %q, want %q", test.fields, err, parsed.Line(), test.line)
		}
	}
	if parsed, _ := ParseOpenRouterKeyUsage([]byte(keyReport(strings.Replace(monthlyFields, `"usage_daily":0.01`, `"usage_daily":7.9e-05`, 1)))); parsed.DailyMicroUSD != 79 {
		t.Fatalf("an exponent amount was not read exactly: %d", parsed.DailyMicroUSD)
	}
}

func TestOpenRouterKeyUsageRefusesMalformedMissingAndOversizedReports(t *testing.T) {
	refused := map[string]string{
		"not JSON":           `{"data":`,
		"no data":            `{"error":{"code":401}}`,
		"data not an object": `{"data":[1]}`,
		"trailing value":     keyReport(monthlyFields) + `{}`,
		"missing monthly":    keyReport(strings.Replace(monthlyFields, `,"usage_monthly":0.079`, "", 1)),
		"missing limit":      keyReport(strings.Replace(monthlyFields, `"limit":50,`, "", 1)),
		"missing reset":      keyReport(strings.Replace(monthlyFields, `"limit_reset":"monthly",`, "", 1)),
		"string amount":      keyReport(strings.Replace(monthlyFields, `"usage":0.079`, `"usage":"0.079"`, 1)),
		"negative amount":    keyReport(strings.Replace(monthlyFields, `"usage":0.079`, `"usage":-1`, 1)),
		"huge amount":        keyReport(strings.Replace(monthlyFields, `"usage":0.079`, `"usage":1e12`, 1)),
		"boolean limit":      keyReport(strings.Replace(monthlyFields, `"limit":50`, `"limit":true`, 1)),
		"reset not a word":   keyReport(strings.Replace(monthlyFields, `"monthly"`, `"Monthly!"`, 1)),
		"reset not a string": keyReport(strings.Replace(monthlyFields, `"monthly"`, `30`, 1)),
		"null usage":         keyReport(strings.Replace(monthlyFields, `"usage":0.079`, `"usage":null`, 1)),
		"oversized":          keyReport(monthlyFields + `,"padding":"` + strings.Repeat("x", 70<<10) + `"`),
		"empty":              ``,
	}
	for name, body := range refused {
		if _, err := ParseOpenRouterKeyUsage([]byte(body)); !errors.Is(err, ErrOpenRouterKeyUnreadable) {
			t.Errorf("%s: a report was accepted: %v", name, err)
		}
		fake := &fakeKeyAPI{status: http.StatusOK, body: body}
		if _, err := ReadOpenRouterKeyUsage(context.Background(), fake, testOpenRouterKey); !errors.Is(err, ErrOpenRouterKeyUnreadable) || strings.Contains(err.Error(), testOpenRouterKey) {
			t.Errorf("%s: read error %v", name, err)
		}
	}
	oversized := &fakeKeyAPI{status: http.StatusOK, body: refused["oversized"]}
	if _, err := ReadOpenRouterKeyUsage(context.Background(), oversized, testOpenRouterKey); err == nil || !strings.Contains(err.Error(), "larger than 64 KiB") {
		t.Fatalf("an oversized report: %v", err)
	}
	// A refusal names only the status; the body is never read into the error.
	denied := &fakeKeyAPI{status: http.StatusUnauthorized, body: `{"error":{"message":"No auth credentials found for ` + testOpenRouterKey + `"}}`}
	if _, err := ReadOpenRouterKeyUsage(context.Background(), denied, testOpenRouterKey); err == nil || err.Error() != "OpenRouter's usage could not be read: OpenRouter answered with HTTP status 401" {
		t.Fatalf("a refused read: %v", err)
	}
	// A redirect is never followed, so the key never goes to another address.
	moved := &fakeKeyAPI{status: http.StatusFound, header: http.Header{"Location": []string{"https://example.test/key"}}}
	if _, err := ReadOpenRouterKeyUsage(context.Background(), moved, testOpenRouterKey); !errors.Is(err, ErrOpenRouterKeyUnreadable) || len(moved.requests) != 1 {
		t.Fatalf("a redirect: %v after %d requests", err, len(moved.requests))
	}
	// A key that could inject a header is refused before any request.
	unused := &fakeKeyAPI{status: http.StatusOK, body: keyReport(monthlyFields)}
	for _, key := range []string{"", "sk-or-v1-a\r\nX-Other: 1", "sk or v1", strings.Repeat("k", 4097)} {
		if _, err := ReadOpenRouterKeyUsage(context.Background(), unused, key); !errors.Is(err, ErrOpenRouterKeyUnreadable) {
			t.Errorf("key %q was used", key)
		}
	}
	if len(unused.requests) != 0 {
		t.Fatalf("an unusable key was sent: %d requests", len(unused.requests))
	}
}
