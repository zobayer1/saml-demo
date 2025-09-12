package main

import (
	"crypto/tls"
	"database/sql"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"idp/config"
	"idp/internal/handlers"
	"idp/internal/services"
	"idp/pkg/db"
	"idp/pkg/session"
)

// version (string): Set at build-time via ldflags
var version = "version:unknown"

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.DebugLevel)
	log.Infof("Identity Provider %s", version)

	cfg, cfgErr := config.NewConfig()
	if cfgErr != nil {
		log.WithError(cfgErr).Fatal("Failed to load configuration")
	}

	session.InitSession(cfg.Secret)

	if dbErr := db.InitDB(cfg.SqliteDb); dbErr != nil {
		log.WithError(dbErr).Fatal("Failed to initialize database")
	}
	defer func(DB *sql.DB) {
		if err := DB.Close(); err != nil {
			log.WithError(err).Error("Failed to close database connection")
		}
	}(db.DB)

	userService := services.NewUserService(db.DB)
	// Initialize signer with same TLS cert/key (demo). Errors are non-fatal; continue unsigned if fails.
	if err := userService.InitSigner(cfg.CertPath, cfg.KeyPath); err != nil {
		log.WithError(err).Warn("Failed to initialize SAML signer; proceeding unsigned")
	}

	authHandler := handlers.NewAuthHandler(userService)
	userHandler := handlers.NewUserHandler(userService)
	ssoHandler := handlers.NewSsoHandler(userService)

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	mux.HandleFunc("/login", authHandler.HandleLogin)
	mux.HandleFunc("/register", userHandler.HandleReg)
	mux.HandleFunc("/sso", ssoHandler.HandleSso)
	mux.HandleFunc("/slo", ssoHandler.HandleSlo)

	mux.HandleFunc("/api/validate-username", userHandler.ValidateUsername)
	mux.HandleFunc("/api/validate-email", userHandler.ValidateEmail)
	mux.HandleFunc("/api/validate-password", userHandler.ValidatePassword)
	mux.HandleFunc("/api/validate-password-match", userHandler.ValidatePasswordMatch)

	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", "inline; filename=\"idp-metadata.xml\"")
		http.ServeFile(w, r, "static/idp-metadata.xml")
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"healthy","service":"idp","timestamp":"` +
			time.Now().UTC().Format(time.RFC3339) + `"}`))
		if err != nil {
			log.WithError(err).Error("Failed to write health response")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	server := &http.Server{
		Addr:    cfg.Host,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		},
	}

	log.Infof("Starting server on %s", cfg.Host)
	if err := server.ListenAndServeTLS(cfg.CertPath, cfg.KeyPath); err != nil {
		log.WithError(err).Fatal("Failed to listen on port 8000")
	}

	log.Info("Server terminated!")
}
