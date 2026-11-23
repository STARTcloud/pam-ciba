package main

import "testing"

func TestTrustedAddress(t *testing.T) {
	trusted := []string{"108.59.188.235", "10.4.0.0/24", "10.12.0.0/24", "2001:db8::/32"}
	cases := map[string]struct {
		remote string
		want   bool
	}{
		"the single address":            {"108.59.188.235", true},
		"inside the first network":      {"10.4.0.140", true},
		"inside the second network":     {"10.12.0.140", true},
		"outside every network":         {"10.16.0.2", false},
		"the neighbour of the address":  {"108.59.188.234", false},
		"an IPv6 address in the prefix": {"2001:db8::1", true},
		"a mapped IPv4 address":         {"::ffff:10.4.0.1", true},
		"a host name":                   {"home.example.org", false},
		"an empty remote":               {"", false},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if got := trustedAddress(trusted, test.remote); got != test.want {
				t.Fatalf("trustedAddress(%q) = %v, want %v", test.remote, got, test.want)
			}
		})
	}
}

func TestTrustedAddressWithNoList(t *testing.T) {
	if trustedAddress(nil, "10.4.0.1") {
		t.Fatal("an empty list trusts an address")
	}
}
