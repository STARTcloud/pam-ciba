package config

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/STARTcloud/pam-ciba/internal/problem"
)

func failure(pointer, rule string, params map[string]any) []problem.Error {
	if params == nil {
		params = map[string]any{}
	}
	return []problem.Error{{Pointer: pointer, Rule: rule, Params: params}}
}

func stringValue(value any) (string, bool) {
	s, ok := value.(string)
	return s, ok
}

func (c *Config) codeRules(pointer string, value any, name string, _ map[string]any, _ string) []problem.Error {
	if name != "app" {
		return nil
	}
	switch pointer {
	case "/provider/issuer":
		s, ok := stringValue(value)
		if !ok || s == "" {
			return nil
		}
		parsed, err := url.Parse(s)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return failure(pointer, "format", map[string]any{"format": "https-issuer"})
		}
	case "/provider/scope":
		s, ok := stringValue(value)
		if !ok || s == "" {
			return nil
		}
		hasOpenID := false
		for _, scope := range strings.Fields(s) {
			if scope == "openid" {
				hasOpenID = true
			}
		}
		if !hasOpenID {
			return failure(pointer, "contains", map[string]any{"value": "openid"})
		}
	case "/approval/trusted_addresses":
		entries, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, entry := range entries {
			s, isString := entry.(string)
			if !isString || !IsAddressOrNetwork(s) {
				return failure(pointer, "format", map[string]any{"format": "ip-or-cidr"})
			}
		}
	}
	return nil
}

// IsAddressOrNetwork reports whether s is one IP address or one CIDR network.
func IsAddressOrNetwork(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}
