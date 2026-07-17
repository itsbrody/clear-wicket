// SPDX-License-Identifier: Apache-2.0
// Copyright Clear Consulting LLC (Wolfgang Brodowski)

package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsbrody/clear-wicket/internal/auth"
	"github.com/itsbrody/clear-wicket/internal/config"
	"github.com/itsbrody/clear-wicket/internal/server"
	"github.com/itsbrody/clear-wicket/internal/store"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset":
			runReset()
			return
		case "healthcheck":
			runHealthcheck()
			return
		}
	}
	runServer()
}

func runServer() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := cfg.EnsureCookieSecret(); err != nil {
		log.Fatalf("cookie secret: %v", err)
	}

	st, err := store.NewFSStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	if cfg.TOTPSecret != "" {
		users, _ := st.ListUsers()
		if len(users) == 0 {
			user := &store.User{
				ID:         "admin",
				TOTPSecret: cfg.TOTPSecret,
				CreatedAt:  time.Now(),
			}
			plaintexts, hashes, err := auth.GenerateBackupCodes(auth.BackupCodeCount)
			if err != nil {
				log.Fatalf("generating backup codes: %v", err)
			}
			user.BackupCodes = hashes
			if err := st.CreateUser(user); err != nil {
				log.Fatalf("creating user: %v", err)
			}
			if err := st.MarkSetupComplete(); err != nil {
				log.Fatalf("marking setup complete: %v", err)
			}
			log.Println("User created from TOTP_SECRET environment variable")
			log.Println("Backup codes (save these now, they will not be shown again):")
			for _, code := range plaintexts {
				log.Printf("  %s", code)
			}
		}
	}

	go sessionCleanup(st)

	srv := server.New(cfg, st)
	log.Fatal(srv.ListenAndServe())
}

func runReset() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	fmt.Printf("This will delete all state in %s and re-open the setup flow.\n", dataDir)
	fmt.Print("Are you sure? [y/N] ")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "y" && answer != "yes" {
		fmt.Println("Aborted.")
		return
	}

	files := []string{"users.json", "sessions.json", "ratelimit.json", "setup_complete"}
	for _, f := range files {
		path := filepath.Join(dataDir, f)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: could not remove %s: %v", path, err)
		}
	}

	fmt.Println("State cleared. Setup flow will be available on next start.")
}

func runHealthcheck() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":4181"
	}
	host := "localhost"
	port := addr
	if strings.HasPrefix(port, ":") {
		port = port[1:]
	}
	url := fmt.Sprintf("http://%s:%s/health", host, port)

	resp, err := http.Get(url)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

func sessionCleanup(st store.Store) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		if err := st.DeleteExpiredSessions(); err != nil {
			log.Printf("session cleanup: %v", err)
		}
	}
}
