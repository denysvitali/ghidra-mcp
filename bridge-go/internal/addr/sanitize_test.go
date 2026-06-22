package addr

import "testing"

func TestSanitize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare hex lowercase", "401000", "0x401000"},
		{"bare hex uppercase", "401ABC", "0x401abc"},
		{"0x hex lowercase", "0x401000", "0x401000"},
		{"0x hex uppercase", "0xDEADBEEF", "0xdeadbeef"},
		{"segment with 0x", "ram:0x401000", "ram:0x401000"},
		{"segment without 0x", "ram:401000", "ram:0x401000"},
		{"overlay segment", "kernel::0xFFFE1234", "kernel::0xFFFE1234"},
		{"overlay without 0x", "kernel::FFFE1234", "kernel::0xfffe1234"},
		{"overlay with mixed case hex preserved", "ram::0xAbCdEf", "ram::0xAbCdEf"},
		{"strips whitespace", "  401000  ", "0x401000"},
		{"underscore segment", "_priv:0x1000", "_priv:0x1000"},
		{"empty", "", ""}, // error returned; below
		{"unknown shape passthrough", "label_name", "label_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.in == "" {
				if _, err := Sanitize(tc.in); err == nil {
					t.Errorf("expected error for empty input")
				}
				return
			}
			got, err := Sanitize(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateHexAddress(t *testing.T) {
	good := []string{
		"401000", "0x401000", "0xDEADBEEF",
		"ram:0x401000", "ram:401000",
		"kernel::0xFFFE1234", "kernel::fffe1234",
		"  401000  ",
	}
	for _, s := range good {
		if !ValidateHexAddress(s) {
			t.Errorf("ValidateHexAddress(%q) = false, want true", s)
		}
	}
	bad := []string{
		"", "xyz", "ram:", "::0x1234", "0xZZZ",
	}
	for _, s := range bad {
		if ValidateHexAddress(s) {
			t.Errorf("ValidateHexAddress(%q) = true, want false", s)
		}
	}
}
