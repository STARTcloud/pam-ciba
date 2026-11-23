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

func TestSSHClientOf(t *testing.T) {
	cases := map[string]struct {
		environ string
		want    string
	}{
		"SSH_CONNECTION wins":     {"HOME=/root\x00SSH_CLIENT=10.4.0.1 1 22\x00SSH_CONNECTION=10.12.0.140 50000 10.7.0.10 22\x00", "10.12.0.140"},
		"SSH_CLIENT alone":        {"SSH_CLIENT=10.4.0.1 1 22\x00", "10.4.0.1"},
		"no SSH variable":         {"HOME=/root\x00TERM=xterm\x00", ""},
		"an empty SSH_CONNECTION": {"SSH_CONNECTION=\x00", ""},
		"an IPv6 client":          {"SSH_CONNECTION=2001:db8::1 50000 2001:db8::2 22\x00", "2001:db8::1"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if got := sshClientOf([]byte(test.environ)); got != test.want {
				t.Fatalf("sshClientOf = %q, want %q", got, test.want)
			}
		})
	}
}

func TestParentPID(t *testing.T) {
	cases := map[string]struct {
		stat string
		want int
	}{
		"a plain line":             {"49085 (sudo) S 49061 49085 49061 34816 49085 4194560 0 0", 49061},
		"a name holding a bracket": {"42 (sh) tricky) S 7 42 42 0 -1", 7},
		"no bracket":               {"garbage", 0},
		"too short":                {"42 (sh) S", 0},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if got := parentPID(test.stat); got != test.want {
				t.Fatalf("parentPID = %d, want %d", got, test.want)
			}
		})
	}
}

func TestTrustedAddressWithNoList(t *testing.T) {
	if trustedAddress(nil, "10.4.0.1") {
		t.Fatal("an empty list trusts an address")
	}
}
