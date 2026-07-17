// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package auth

import (
	"net/url"
	"strings"
)

func BuildRedirectURL(proto, host, uri string) string {
	if proto == "" {
		proto = "https"
	}
	if host == "" {
		return ""
	}
	return proto + "://" + host + uri
}

func ValidateRedirectURL(target, cookieDomain string) bool {
	if target == "" {
		return false
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	host := parsed.Hostname()
	if host == "" {
		return false
	}

	domain := cookieDomain
	if strings.HasPrefix(domain, ".") {
		domain = domain[1:]
	}

	if host == domain || strings.HasSuffix(host, "."+domain) {
		return true
	}

	return false
}
