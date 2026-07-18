package clientidentity

import "testing"

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"srv-u-makame-device-1":               "u-makame-device-1",
		"u-makame-device-1@1784398210646":     "u-makame-device-1",
		"srv-u-makame-device-1@1784398210646": "u-makame-device-1",
		"user@example.com":                    "user@example.com",
		"device@123":                          "device@123",
	}
	for input, want := range tests {
		if got := Normalize(input); got != want {
			t.Fatalf("Normalize(%q) = %q, want %q", input, got, want)
		}
	}
}
