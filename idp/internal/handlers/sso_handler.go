package handlers

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"idp/internal/models"
	"idp/internal/services"
	"idp/pkg/session"
)

type SsoHandler struct{ userService *services.UserService }

func NewSsoHandler(userService *services.UserService) *SsoHandler {
	return &SsoHandler{userService: userService}
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

	// Retrieve and deserialize user session to determine authentication status
	userSessionCookie, err := session.Store.Get(r, "user-session")
	if err != nil {
		log.WithError(err).Error("Session store corruption detected during login validation")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rawUserSession, ok := userSessionCookie.Values["user-session"].(string); ok && rawUserSession != "" {
		userSess, deserErr := models.DeserializeUserSession(rawUserSession)
		if deserErr != nil {
			log.WithError(deserErr).Warn("Failed to deserialize stored user session - treating as unauthenticated")
		} else if userSess.IsAuthenticated {
			log.WithFields(log.Fields{
				"user":       userSess.Email,
				"session_id": userSess.SessionID,
				"sp":         authnRequest.Issuer.Value,
				"req_id":     authnRequest.ID,
			}).Info("User already authenticated - generating SAML response")

			// Build response immediately
			samlResp, respErr := h.userService.BuildSAMLResponse(*userSess, samlContext)
			if respErr != nil {
				log.WithError(respErr).Error("Failed to build SAML response for existing session")
				http.Error(w, "Failed to build SAML response", http.StatusInternalServerError)
				return
			}

			// One-time context use - clear session context
			delete(samlSession.Values, "saml-context")
			if err := samlSession.Save(r, w); err != nil {
				log.WithError(err).Warn("Failed to clear saml-context after response generation")
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>SAML Redirect</title></head><body onload="document.forms[0].submit()">`)
			_, _ = fmt.Fprintf(w, `<form method="post" action="%s">`, template.HTMLEscapeString(samlContext.AssertionConsumerServiceURL))
			_, _ = fmt.Fprintf(w, `<input type="hidden" name="SAMLResponse" value="%s"/>`, template.HTMLEscapeString(samlResp))
			if relayState != "" {
				_, _ = fmt.Fprintf(w, `<input type="hidden" name="RelayState" value="%s"/>`, template.HTMLEscapeString(relayState))
			}
			_, _ = fmt.Fprintf(w, `<noscript><p>JavaScript disabled. Click continue.</p><button type="submit">Continue</button></noscript></form></body></html>`)
			return
		}
	} else {
		log.Debug("User session key missing or empty - unauthenticated")
	}

	// User not authenticated - redirect to login page
	log.WithField("sp", authnRequest.Issuer.Value).Info("User not authenticated - redirecting to login for SAML flow")

	// Generate login URL with context marker
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
