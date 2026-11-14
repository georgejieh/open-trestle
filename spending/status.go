package spending

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Note is the sentence every spending message carries: what the figures are
// and what the limit is not.
const Note = "Spending figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill; the limit is best effort, and your provider's own limit is the guarantee."

// Status is one limit with what the ledger records against it in the
// current period.
type Status struct {
	Limit      Limit
	Start, End time.Time
	Spend      Spend
}

// CurrentStatus reads the spend against limit in the period that contains at.
func (s *Store) CurrentStatus(limit Limit, at time.Time) (Status, error) {
	start, end := limit.Period.Bounds(at)
	spend, err := s.Spent(limit.Scope, start, end)
	if err != nil {
		return Status{}, err
	}
	return Status{Limit: limit, Start: start, End: end, Spend: spend}, nil
}

// Reached reports recorded spend at or over the limit.
func (s Status) Reached() bool { return s.Spend.MicroUSD >= s.Limit.AmountMicroUSD }

// Percent is the recorded spend as a whole percentage of the limit, rounded
// down.
func (s Status) Percent() uint64 { return percentOf(s.Spend.MicroUSD, s.Limit.AmountMicroUSD) }

// WouldCross reports whether adding worst to the recorded spend could reach
// the limit.
func (s Status) WouldCross(worst uint64) bool {
	return worst > 0 && (s.Spend.MicroUSD > ^uint64(0)-worst || s.Spend.MicroUSD+worst >= s.Limit.AmountMicroUSD)
}

func percentOf(value, whole uint64) uint64 {
	if whole == 0 {
		return 0
	}
	quotient := new(big.Int).Mul(new(big.Int).SetUint64(value), big.NewInt(100))
	quotient.Quo(quotient, new(big.Int).SetUint64(whole))
	if !quotient.IsUint64() {
		return ^uint64(0)
	}
	return quotient.Uint64()
}

// threshold is the spend at which an alert percentage is reached, rounded up.
func threshold(limit uint64, percent int) uint64 {
	value := new(big.Int).Mul(new(big.Int).SetUint64(limit), big.NewInt(int64(percent)))
	value.Add(value, big.NewInt(99))
	value.Quo(value, big.NewInt(100))
	return value.Uint64()
}

// CrossedAlert returns the highest alert percentage that recorded spend
// reached when it went from before to after, or false when none was crossed.
func CrossedAlert(limit Limit, before, after uint64) (int, bool) {
	crossed, found := 0, false
	for _, percent := range limit.AlertPercents {
		at := threshold(limit.AmountMicroUSD, percent)
		if before < at && after >= at {
			crossed, found = percent, true
		}
	}
	return crossed, found
}

// FormatUSD writes an amount in dollars with two decimals, rounded up to the
// cent, as an upper-bound estimate should be: $8.12, $0.01, $0.00.
func FormatUSD(micro uint64) string {
	cents := micro / microUSDPerCent
	if micro%microUSDPerCent != 0 {
		cents++
	}
	return fmt.Sprintf("$%d.%02d", cents/100, cents%100)
}

// ParseUSD reads an amount in dollars with at most two decimals, such as 10,
// 10.5 or $0.25, into micro-USD.
func ParseUSD(value string) (uint64, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "$")
	whole, fraction, hasFraction := strings.Cut(value, ".")
	if whole == "" {
		whole = "0"
	}
	if hasFraction && fraction == "" || len(fraction) > 2 || len(whole) > 7 || strings.Trim(whole, "0123456789") != "" || strings.Trim(fraction, "0123456789") != "" {
		return 0, fmt.Errorf("type an amount in US dollars with at most two decimals, such as 10 or 25.50")
	}
	fraction += strings.Repeat("0", 2-len(fraction))
	cents, err := strconv.ParseUint(whole+fraction, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("type an amount in US dollars with at most two decimals, such as 10 or 25.50")
	}
	return cents * microUSDPerCent, nil
}

// ParseAlerts reads comma-separated alert percentages, such as 80,100.
func ParseAlerts(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	alerts := make([]int, 0, len(parts))
	for _, part := range parts {
		percent, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(part), "%"))
		if err != nil || percent < 1 || percent > 100 || len(alerts) > 0 && percent <= alerts[len(alerts)-1] || len(alerts) == maxAlerts {
			return nil, fmt.Errorf("give alert percentages as ascending whole numbers from 1 to 100, such as 80,100")
		}
		alerts = append(alerts, percent)
	}
	return alerts, nil
}

// AlertList writes alert percentages for people: "80% and 100%".
func AlertList(alerts []int) string {
	parts := make([]string, len(alerts))
	for i, percent := range alerts {
		parts[i] = strconv.Itoa(percent) + "%"
	}
	if len(parts) <= 1 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// Describe is the limit itself: "$10.00 monthly limit".
func (l Limit) Describe() string {
	return FormatUSD(l.AmountMicroUSD) + " " + l.Period.Adjective() + " limit"
}

// Summary is the status in one clause: "$0.60 of your $10.00 monthly limit
// for OPEN_TRESTLE_PROVIDER_OPENROUTER this month (6%), alerts at 80% and
// 100%".
func (s Status) Summary() string {
	return fmt.Sprintf("%s of your %s for %s %s (%d%%), alerts at %s", FormatUSD(s.Spend.MicroUSD), s.Limit.Describe(), s.Limit.Scope.CredentialEnvironment, s.Limit.Period.Current(), s.Percent(), AlertList(s.Limit.AlertPercents))
}

// AlertLine is printed once when a review's spend crosses an alert
// percentage.
func (s Status) AlertLine() string {
	return fmt.Sprintf("Spending alert: %s of your %s for %s (%d%%)", FormatUSD(s.Spend.MicroUSD), s.Limit.Describe(), s.Limit.Scope.CredentialEnvironment, s.Percent())
}

// ReachedLine explains a review refused because the limit is reached.
func (s Status) ReachedLine() string {
	return fmt.Sprintf("Spending limit reached: %s of your %s for %s (%d%%) is recorded %s, so this review was not started and nothing was sent. Run trestle usage to see it; raise or clear the limit with trestle usage set or trestle usage clear, or wait until the %s ends.", FormatUSD(s.Spend.MicroUSD), s.Limit.Describe(), s.Limit.Scope.CredentialEnvironment, s.Percent(), s.Limit.Period.Current(), s.Limit.Period)
}

// WarningLine says a review may take recorded spend past the limit; it runs.
func (s Status) WarningLine(worst uint64) string {
	return fmt.Sprintf("Spending warning: this review may cost up to %s, which could take the %s recorded %s past your %s for %s; it runs anyway.", FormatUSD(worst), FormatUSD(s.Spend.MicroUSD), s.Limit.Period.Current(), s.Limit.Describe(), s.Limit.Scope.CredentialEnvironment)
}
