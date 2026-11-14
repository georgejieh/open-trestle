package spending

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// OpenRouter reports a key's usage and limit at one address. Reading it costs
// nothing and sends no source: one GET with the key as a bearer credential.
const (
	OpenRouterKeyURL      = "https://openrouter.ai/api/v1/key"
	openRouterKeyMaxBytes = 64 << 10
	openRouterKeyTimeout  = 10 * time.Second
	// maxReportedUSD bounds every amount read from the report.
	maxReportedUSD = 1_000_000_000
)

// ErrOpenRouterKeyUnreadable is any failure to read or parse the report. It
// never carries the key or the response body.
var ErrOpenRouterKeyUnreadable = errors.New("OpenRouter's usage could not be read")

// OpenRouterKeyUsage is the bounded numeric part of OpenRouter's report for
// one key, in micro-US-dollars, and the word that names when its limit
// resets. Nothing else is read: in particular the label, which holds a masked
// form of the key, is never decoded.
type OpenRouterKeyUsage struct {
	HasLimit               bool
	LimitMicroUSD          uint64
	HasLimitRemaining      bool
	LimitRemainingMicroUSD uint64
	// LimitReset is "" when the limit never resets, else a lowercase word
	// such as daily, weekly or monthly.
	LimitReset                                                    string
	UsageMicroUSD, DailyMicroUSD, WeeklyMicroUSD, MonthlyMicroUSD uint64
}

var jsonNumber = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// reportedMicroUSD reads one JSON number of US dollars: non-negative, at most
// maxReportedUSD, rounded up to a micro-dollar.
func reportedMicroUSD(raw json.RawMessage) (uint64, error) {
	text := string(bytes.TrimSpace(raw))
	if len(text) == 0 || len(text) > 40 || !jsonNumber.MatchString(text) {
		return 0, ErrOpenRouterKeyUnreadable
	}
	value, ok := new(big.Rat).SetString(text)
	if !ok || value.Sign() < 0 || value.Cmp(new(big.Rat).SetInt64(maxReportedUSD)) > 0 {
		return 0, ErrOpenRouterKeyUnreadable
	}
	value.Mul(value, new(big.Rat).SetInt64(1_000_000))
	micro := new(big.Int).Quo(value.Num(), value.Denom())
	if new(big.Rat).SetInt(micro).Cmp(value) < 0 {
		micro.Add(micro, big.NewInt(1))
	}
	return micro.Uint64(), nil
}

func isNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

// ParseOpenRouterKeyUsage reads OpenRouter's key report. It requires a data
// object whose usage, usage_daily, usage_weekly and usage_monthly are numbers,
// whose limit and limit_remaining are numbers or null, and whose limit_reset
// is null or one short lowercase word. Every other member is ignored unread.
func ParseOpenRouterKeyUsage(body []byte) (OpenRouterKeyUsage, error) {
	if len(body) == 0 || len(body) > openRouterKeyMaxBytes {
		return OpenRouterKeyUsage{}, ErrOpenRouterKeyUnreadable
	}
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&envelope) != nil || envelope.Data == nil {
		return OpenRouterKeyUsage{}, ErrOpenRouterKeyUnreadable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return OpenRouterKeyUsage{}, ErrOpenRouterKeyUnreadable
	}
	var usage OpenRouterKeyUsage
	for name, target := range map[string]*uint64{"usage": &usage.UsageMicroUSD, "usage_daily": &usage.DailyMicroUSD, "usage_weekly": &usage.WeeklyMicroUSD, "usage_monthly": &usage.MonthlyMicroUSD} {
		raw, ok := envelope.Data[name]
		if !ok {
			return OpenRouterKeyUsage{}, fmt.Errorf("%w: the report has no %s", ErrOpenRouterKeyUnreadable, name)
		}
		value, err := reportedMicroUSD(raw)
		if err != nil {
			return OpenRouterKeyUsage{}, fmt.Errorf("%w: %s is not a usable amount", ErrOpenRouterKeyUnreadable, name)
		}
		*target = value
	}
	for _, field := range []struct {
		name  string
		has   *bool
		value *uint64
	}{{"limit", &usage.HasLimit, &usage.LimitMicroUSD}, {"limit_remaining", &usage.HasLimitRemaining, &usage.LimitRemainingMicroUSD}} {
		raw, ok := envelope.Data[field.name]
		if !ok {
			return OpenRouterKeyUsage{}, fmt.Errorf("%w: the report has no %s", ErrOpenRouterKeyUnreadable, field.name)
		}
		if isNull(raw) {
			continue
		}
		value, err := reportedMicroUSD(raw)
		if err != nil {
			return OpenRouterKeyUsage{}, fmt.Errorf("%w: %s is not a usable amount", ErrOpenRouterKeyUnreadable, field.name)
		}
		*field.has, *field.value = true, value
	}
	raw, ok := envelope.Data["limit_reset"]
	if !ok {
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: the report has no limit_reset", ErrOpenRouterKeyUnreadable)
	}
	if !isNull(raw) {
		var word string
		if json.Unmarshal(raw, &word) != nil || len(word) == 0 || len(word) > 16 || strings.ContainsFunc(word, func(r rune) bool { return r < 'a' || r > 'z' }) {
			return OpenRouterKeyUsage{}, fmt.Errorf("%w: limit_reset is not a reset period", ErrOpenRouterKeyUnreadable)
		}
		usage.LimitReset = word
	}
	return usage, nil
}

// Line is OpenRouter's figures in one sentence, for example "OpenRouter
// reports $0.08 used this month of this key's $50.00 monthly limit".
func (u OpenRouterKeyUsage) Line() string {
	used, when := u.UsageMicroUSD, "in total"
	switch u.LimitReset {
	case "daily":
		used, when = u.DailyMicroUSD, "today"
	case "weekly":
		used, when = u.WeeklyMicroUSD, "this week"
	case "monthly":
		used, when = u.MonthlyMicroUSD, "this month"
	}
	if !u.HasLimit {
		return fmt.Sprintf("OpenRouter reports %s used this month; this key has no OpenRouter limit (set one in OpenRouter's key settings for a hard cap)", FormatUSD(u.MonthlyMicroUSD))
	}
	switch u.LimitReset {
	case "":
		return fmt.Sprintf("OpenRouter reports %s used %s of this key's %s limit", FormatUSD(used), when, FormatUSD(u.LimitMicroUSD))
	case "daily", "weekly", "monthly":
		return fmt.Sprintf("OpenRouter reports %s used %s of this key's %s %s limit", FormatUSD(used), when, FormatUSD(u.LimitMicroUSD), u.LimitReset)
	}
	return fmt.Sprintf("OpenRouter reports %s used in total of this key's %s limit (reset: %s)", FormatUSD(used), FormatUSD(u.LimitMicroUSD), u.LimitReset)
}

// ReadOpenRouterKeyUsage sends one GET to OpenRouterKeyURL with key as the
// bearer credential and parses the report. It follows no redirect, reads at
// most 64 KiB and waits at most ten seconds. A nil transport uses a direct
// HTTPS transport without a proxy. The returned error never carries the key
// or the response body.
func ReadOpenRouterKeyUsage(ctx context.Context, transport http.RoundTripper, key string) (OpenRouterKeyUsage, error) {
	if ctx == nil || key == "" || len(key) > 4096 || strings.ContainsFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII }) {
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: the key variable does not hold a usable key", ErrOpenRouterKeyUnreadable)
	}
	if transport == nil {
		transport = &http.Transport{
			Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: true,
			MaxResponseHeaderBytes: 64 << 10, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		}
	}
	client := &http.Client{Transport: transport, Timeout: openRouterKeyTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	}}
	requestCtx, cancel := context.WithTimeout(ctx, openRouterKeyTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, OpenRouterKeyURL, nil)
	if err != nil {
		return OpenRouterKeyUsage{}, ErrOpenRouterKeyUnreadable
	}
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "open-trestle/1 (key usage)")
	response, err := client.Do(request)
	if err != nil {
		if requestCtx.Err() != nil {
			return OpenRouterKeyUsage{}, fmt.Errorf("%w: no answer within 10 seconds", ErrOpenRouterKeyUnreadable)
		}
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: OpenRouter could not be reached", ErrOpenRouterKeyUnreadable)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: OpenRouter answered with HTTP status %d", ErrOpenRouterKeyUnreadable, response.StatusCode)
	}
	if response.ContentLength > openRouterKeyMaxBytes {
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: the report is larger than 64 KiB", ErrOpenRouterKeyUnreadable)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, openRouterKeyMaxBytes+1))
	if err != nil {
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: the report could not be read completely", ErrOpenRouterKeyUnreadable)
	}
	if len(body) > openRouterKeyMaxBytes {
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: the report is larger than 64 KiB", ErrOpenRouterKeyUnreadable)
	}
	usage, err := ParseOpenRouterKeyUsage(body)
	if err != nil {
		if errors.Is(err, ErrOpenRouterKeyUnreadable) && err.Error() != ErrOpenRouterKeyUnreadable.Error() {
			return OpenRouterKeyUsage{}, err
		}
		return OpenRouterKeyUsage{}, fmt.Errorf("%w: the report is not in the expected format", ErrOpenRouterKeyUnreadable)
	}
	return usage, nil
}
