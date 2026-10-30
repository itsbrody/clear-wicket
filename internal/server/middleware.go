// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package server

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d %s %s", r.Method, r.URL.Path, rw.status, time.Since(start), clientIP(r))
	})
}

func withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders sets the security headers on every response. Without
// frameAncestors, framing is denied. With it, only the CSP frame-ancestors
// directive is sent: X-Frame-Options cannot name a foreign origin and some
// browsers would let it override the CSP.
func withSecurityHeaders(frameAncestors []string, next http.Handler) http.Handler {
	csp := "frame-ancestors 'none'"
	if len(frameAncestors) > 0 {
		csp = "frame-ancestors " + strings.Join(frameAncestors, " ")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if len(frameAncestors) == 0 {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i != -1 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
