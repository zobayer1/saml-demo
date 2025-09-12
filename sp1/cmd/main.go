package main

import (
	"crypto/tls"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"sp1/config"
)

// version (string): Set at build-time via ldflags
var version = "version:unknown"

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.DebugLevel)
	log.Infof("Service#1 Provider %s\n", version)

	cfg, cfgErr := config.NewConfig()
	if cfgErr != nil {
		log.WithError(cfgErr).Fatal("Failed to load configuration")
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", "inline; filename=\"sp1-metadata.xml\"")
		http.ServeFile(w, r, "static/sp1-metadata.xml")
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"healthy","service":"sp1","timestamp":"` +
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
