package handlers

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"idp/internal/models"
	"idp/pkg/session"
)

type SsoHandler struct{}

func NewSsoHandler() *SsoHandler {
	return &SsoHandler{}
}

func (h *SsoHandler) HandleSso(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var samlRequest, relayState string

	if r.Method == http.MethodGet {
		samlRequest = r.URL.Query().Get("SAMLRequest")
		relayState = r.URL.Query().Get("RelayState")
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			log.WithError(err).Error("Failed to parse form data")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		samlRequest = r.FormValue("SAMLRequest")
		relayState = r.FormValue("RelayState")
	}

	if samlRequest == "" {
		log.Error("Missing SAMLRequest parameter")
		http.Error(w, "Missing SAMLRequest parameter", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		samlRequest = strings.ReplaceAll(samlRequest, " ", "+")
	}

	decodedSAMLRequest, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		log.WithError(err).Errorf("Standard base64 decode failed")
		http.Error(w, "Malformed base64 encoded SAMLRequest", http.StatusBadRequest)
		return
	} else {
		log.Debugf("Successfully decoded SAMLRequest using standard base64:\n%v", decodedSAMLRequest)
	}

	reader := flate.NewReader(bytes.NewReader(decodedSAMLRequest))
	defer func() {
		if err := reader.Close(); err != nil {
			log.Warnf("Error closing flate reader: stream was not deflated")
		}
	}()
	xmlData, err := io.ReadAll(reader)
	if err != nil {
		log.Warn("Inflation failed, treating as uncompressed")
		xmlData = decodedSAMLRequest
	} else {
		log.Debug("Successfully inflated SAMLRequest")
	}

	var authnRequest models.AuthnRequest
	err = xml.Unmarshal(xmlData, &authnRequest)
	if err != nil {
		log.WithError(err).Error("Failed to parse SAML AuthnRequest XML")
		http.Error(w, "Invalid SAML AuthnRequest XML", http.StatusBadRequest)
		return
	}

	log.Debugf("Parsed SAML AuthnRequest:")
	log.Debugf("  ID: %s", authnRequest.ID)
	log.Debugf("  Version: %s", authnRequest.Version)
	log.Debugf("  IssueInstant: %s", authnRequest.IssueInstant)
	log.Debugf("  Destination: %s", authnRequest.Destination)
	log.Debugf("  AssertionConsumerServiceURL: %s", authnRequest.AssertionConsumerServiceURL)
	log.Debugf("  ProtocolBinding: %s", authnRequest.ProtocolBinding)
	log.Debugf("  Issuer: %s", authnRequest.Issuer.Value)
	log.Debugf("RelayState: %s", relayState)

	// Store SAML request context in session using the proper struct
	samlSession, err := session.Store.Get(r, "saml-context")
	if err != nil {
		log.WithError(err).Error("Failed to get SAML context session")
	}

	// Parse IssueInstant string to time.Time
	issueInstant, err := time.Parse(time.RFC3339, authnRequest.IssueInstant)
	if err != nil {
		log.WithError(err).Warn("Failed to parse IssueInstant, using current time")
		issueInstant = time.Now()
	}

	// Create SAMLRequestContext struct with all the data
	samlContext := models.SAMLRequestContext{
		RequestID:                   authnRequest.ID,
		Issuer:                      authnRequest.Issuer.Value,
		AssertionConsumerServiceURL: authnRequest.AssertionConsumerServiceURL,
		RelayState:                  relayState,
		ProtocolBinding:             authnRequest.ProtocolBinding,
		Destination:                 authnRequest.Destination,
		IssueInstant:                issueInstant,
		RequestTimestamp:            time.Now(),
	}

	// Store the entire struct in session using explicit serialization
	serializedContext, err := samlContext.Serialize()
	if err != nil {
		log.WithError(err).Error("Failed to serialize SAML context")
		http.Error(w, "Session serialization error", http.StatusInternalServerError)
		return
	}

	samlSession.Values["saml-context"] = serializedContext

	if err := samlSession.Save(r, w); err != nil {
		log.WithError(err).Error("Failed to save SAML context session")
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	log.Debugf("SAML request context serialized and stored in session: %+v", samlContext)

	// TODO: Check user authentication
	userSession, err := session.Store.Get(r, "user-session")
	if err != nil {
		log.WithError(err).Error("Failed to get user session")
	}

	// Check if user is already authenticated
	if isAuth, exists := userSession.Values["is_authenticated"]; exists && isAuth == true {
		log.Info("User already authenticated - proceeding to SAML response generation")
		// TODO: Generate SAML response
		http.Error(w, fmt.Sprintf("User authenticated. Ready to generate SAML response for SP: %s",
			authnRequest.Issuer.Value), http.StatusNotImplemented)
		return
	}

	// User not authenticated - redirect to login page
	log.Info("User not authenticated - redirecting to login")

	// Generate login URL with context
	loginURL := "/login?saml=true"
	log.Debugf("Redirecting to login: %s", loginURL)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *SsoHandler) HandleSlo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	http.Error(w, "Not Implemented", http.StatusNotImplemented)
}
