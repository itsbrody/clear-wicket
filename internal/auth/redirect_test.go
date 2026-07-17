// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import "testing"

func TestBuildRedirectURL(t *testing.T) {
	tests := []struct {
		proto, host, uri, want string
	}{
		{"https", "app.example.com", "/dashboard", "https://app.example.com/dashboard"},
		{"http", "app.example.com", "/", "http://app.example.com/"},
		{"", "app.example.com", "/path", "https://app.example.com/path"},
		{"https", "", "/path", ""},
	}
	for _, tc := range tests {
		got := BuildRedirectURL(tc.proto, tc.host, tc.uri)
		if got != tc.want {
			t.Errorf("BuildRedirectURL(%q, %q, %q) = %q, want %q", tc.proto, tc.host, tc.uri, got, tc.want)
		}
	}
}

func TestValidateRedirectURL(t *testing.T) {
	tests := []struct {
		target       string
		cookieDomain string
		want         bool
	}{
		// Valid: exact domain
		{"https://example.com/app", "example.com", true},
		// Valid: subdomain
		{"https://app.example.com/dashboard", "example.com", true},
		{"https://app.example.com/dashboard", ".example.com", true},
		// Valid: deep subdomain
		{"https://deep.sub.example.com/path", "example.com", true},
		// Invalid: different domain
		{"https://evil.com/app", "example.com", false},
		// Invalid: domain suffix attack
		{"https://notexample.com/app", "example.com", false},
		// Invalid: empty
		{"", "example.com", false},
		// Invalid: javascript scheme
		{"javascript:alert(1)", "example.com", false},
		// Invalid: no scheme
		{"//evil.com/app", "example.com", false},
		// Invalid: data URI
		{"data:text/html,<h1>evil</h1>", "example.com", false},
	}
	for _, tc := range tests {
		got := ValidateRedirectURL(tc.target, tc.cookieDomain)
		if got != tc.want {
			t.Errorf("ValidateRedirectURL(%q, %q) = %v, want %v", tc.target, tc.cookieDomain, got, tc.want)
		}
	}
}
