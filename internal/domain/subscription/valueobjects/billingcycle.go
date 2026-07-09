package valueobjects

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrInvalidBillingCycle is returned when billing cycle is not valid
	ErrInvalidBillingCycle = errors.New("invalid billing cycle")
)

type BillingCycle string

const (
	BillingCycleWeekly     BillingCycle = "weekly"
	BillingCycleMonthly    BillingCycle = "monthly"
	BillingCycleQuarterly  BillingCycle = "quarterly"
	BillingCycleSemiAnnual BillingCycle = "semi_annual"
	BillingCycleYearly     BillingCycle = "yearly"
	BillingCycleLifetime   BillingCycle = "lifetime"
)

var ValidBillingCycles = map[BillingCycle]bool{
	BillingCycleWeekly:     true,
	BillingCycleMonthly:    true,
	BillingCycleQuarterly:  true,
	BillingCycleSemiAnnual: true,
	BillingCycleYearly:     true,
	BillingCycleLifetime:   true,
}

var BillingCycleDays = map[BillingCycle]int{
	BillingCycleWeekly:     7,
	BillingCycleMonthly:    30,
	BillingCycleQuarterly:  90,
	BillingCycleSemiAnnual: 180,
	BillingCycleYearly:     365,
	BillingCycleLifetime:   0,
}

func NewBillingCycle(value string) (*BillingCycle, error) {
	cycle := BillingCycle(value)

	if value == "" {
		return nil, fmt.Errorf("billing cycle cannot be empty")
	}

	if !ValidBillingCycles[cycle] {
		return nil, fmt.Errorf("invalid billing cycle: %s", value)
	}

	return &cycle, nil
}

func ParseBillingCycle(value string) (BillingCycle, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	cycle := BillingCycle(normalized)

	if normalized == "" {
		return "", fmt.Errorf("billing cycle cannot be empty")
	}

	if !ValidBillingCycles[cycle] {
		return "", fmt.Errorf("invalid billing cycle: %s", value)
	}

	return cycle, nil
}

func (b BillingCycle) String() string {
	return string(b)
}

func (b BillingCycle) IsValid() bool {
	return ValidBillingCycles[b]
}

func (b BillingCycle) Days() int {
	days, exists := BillingCycleDays[b]
	if !exists {
		return 0
	}
	return days
}

// NextBillingDate returns the end of a billing period that starts at `from`.
//
// It uses fixed day counts (not calendar arithmetic) so period lengths stay
// consistent and do not "drift" when a period starts on a month boundary
// (e.g. Jan 31 -> Feb 28 -> Mar 28). This is the single canonical period-length
// calculation: subscription creation, plan changes, and renewal all go through
// it, so the same cycle always yields the same period length.
func (b BillingCycle) NextBillingDate(from time.Time) time.Time {
	switch b {
	case BillingCycleWeekly:
		return from.Add(7 * 24 * time.Hour)
	case BillingCycleMonthly:
		return from.Add(31 * 24 * time.Hour)
	case BillingCycleQuarterly:
		return from.Add(93 * 24 * time.Hour) // 31 * 3
	case BillingCycleSemiAnnual:
		return from.Add(180 * 24 * time.Hour)
	case BillingCycleYearly:
		return from.Add(365 * 24 * time.Hour)
	case BillingCycleLifetime:
		// Effectively never expires. Use Jan 1 (not Dec 31 23:59:59) to avoid
		// year overflow when converting to eastern timezones.
		return time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	default:
		return from.Add(31 * 24 * time.Hour)
	}
}

func (b BillingCycle) IsLifetime() bool {
	return b == BillingCycleLifetime
}

func (b BillingCycle) Equals(other BillingCycle) bool {
	return b == other
}

func (b BillingCycle) MarshalJSON() ([]byte, error) {
	return []byte(`"` + b.String() + `"`), nil
}

func (b *BillingCycle) UnmarshalJSON(data []byte) error {
	str := string(data)
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		str = str[1 : len(str)-1]
	}

	cycle, err := NewBillingCycle(str)
	if err != nil {
		return err
	}

	*b = *cycle
	return nil
}
