package utils

import "testing"

func TestCalculateSavingRate(t *testing.T) {
	tests := []struct {
		name         string
		monthlyPrice uint64
		totalPrice   uint64
		months       int
		want         float32
	}{
		{"typical discount", 1000, 8000, 12, 33.333336}, // ¥120 expected vs ¥80 paid
		{"no discount", 1000, 12000, 12, 0},
		// The discounted total is actually MORE expensive than paying monthly.
		// Unsigned subtraction must not wrap around into "100% savings".
		{"worse than monthly", 1000, 15000, 12, 0},
		{"zero months", 1000, 8000, 0, 0},
		{"zero monthly price", 0, 8000, 12, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateSavingRate(tt.monthlyPrice, tt.totalPrice, tt.months)
			if got != tt.want {
				t.Fatalf("CalculateSavingRate(%d, %d, %d) = %v, want %v",
					tt.monthlyPrice, tt.totalPrice, tt.months, got, tt.want)
			}
		})
	}
}
