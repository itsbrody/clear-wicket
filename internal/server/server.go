// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package server

import (
	"log"
	"net/http"

	"github.com/itsbrody/clear-wicket/internal/config"
	"github.com/itsbrody/clear-wicket/internal/store"
)

type Server struct {
	cfg   *config.Config
	store store.Store
	mux   *http.ServeMux
}

func New(cfg *config.Config, s store.Store) *Server {
	srv := &Server{
		cfg:   cfg,
		store: s,
		mux:   http.NewServeMux(),
	}
	srv.routes()
	return srv
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /auth", s.handleAuth)
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /setup", s.handleSetupPage)
	s.mux.HandleFunc("POST /setup", s.handleSetupSubmit)
	s.mux.HandleFunc("POST /setup/confirm", s.handleSetupConfirmBackups)
	s.mux.HandleFunc("GET /backup-codes/regenerate", s.handleRegenerateBackupCodesPage)
	s.mux.HandleFunc("POST /backup-codes/regenerate", s.handleRegenerateBackupCodes)
	s.mux.HandleFunc("GET /logout", s.handleLogout)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := withSecurityHeaders(withRecovery(withRequestLogging(s.mux)))
	handler.ServeHTTP(w, r)
}

func (s *Server) ListenAndServe() error {
	log.Printf("Clear Wicket listening on %s", s.cfg.ListenAddr)
	return http.ListenAndServe(s.cfg.ListenAddr, s)
}
