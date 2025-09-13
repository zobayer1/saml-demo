package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"idp/internal/helpers"
	"idp/internal/models"
	"idp/internal/services"
	"idp/pkg/session"
)

type AuthHandler struct {
	userService *services.UserService
}

func NewAuthHandler(userService *services.UserService) *AuthHandler {
	return &AuthHandler{userService: userService}
}

func (h *AuthHandler) renderLoginPage(w http.ResponseWriter, data models.LoginPageData) {
	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "base.html"),
		filepath.Join("internal", "templates", "partials", "login.html"),
	))
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *AuthHandler) getLoginForm(w http.ResponseWriter, r *http.Request) {
	data := models.LoginPageData{
		PageData: models.PageData{
			Title: "Login - MyIDP",
			Page:  "login",
		},
		SAMLState: models.SAMLState{
			SAMLFlow:   false,
			SPName:     "",
			SPEntityID: "",
		},
		UserSession: models.UserSession{IsAuthenticated: false},
	}

	isSAMLParam := r.URL.Query().Get("saml") == "true"

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	samlSession, err := session.Store.Get(r, "saml-context")
	if err != nil {
		log.WithError(err).Error("Session store corrupted")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var samlContext *models.SAMLRequestContext
	if contextData, exists := samlSession.Values["saml-context"]; exists {
		if contextStr, ok := contextData.(string); ok && len(contextStr) > 0 {
			if ctx, serdeErr := models.DeserializeSAMLRequestContext(contextStr); serdeErr == nil {
				samlContext = ctx
				data.SAMLState = models.SAMLState{
					SAMLFlow:   true,
					SPName:     helpers.ExtractSPName(ctx.Issuer),
					SPEntityID: ctx.Issuer,
				}
				log.Debugf("SAML flow detected from session - SP: %s", ctx.Issuer)
			} else {
				log.WithError(serdeErr).Error("Failed to deserialize SAML context")
				http.Error(w, serdeErr.Error(), http.StatusInternalServerError)
				return
			}
		} else if isSAMLParam {
			log.Error("SAML context not found in session")
			data.Error = "SAML session expired. Please try again from your application."
		}
	} else if isSAMLParam {
		data.Error = "SAML session expired. Please try again from your application."
	}

	userSessionCookie, err := session.Store.Get(r, "user-session")
	if err != nil {
		log.WithError(err).Error("Failed to load user-session cookie")
	} else if rawUserSession, ok := userSessionCookie.Values["user-session"].(string); ok && rawUserSession != "" {
		if userSess, deserErr := models.DeserializeUserSession(rawUserSession); deserErr == nil && userSess.IsAuthenticated {
			data.UserSession = *userSess

			if samlContext != nil {
				log.WithFields(
					log.Fields{"user": userSess.Email, "sp": samlContext.Issuer, "req_id": samlContext.RequestID},
				).Info("Authenticated user hitting login during SAML flow - auto-responding")
				samlResp, buildErr := h.userService.BuildSAMLResponse(*userSess, *samlContext)
				if buildErr != nil {
					log.WithError(buildErr).Error("Failed to build SAML response in login auto-redirect")
					http.Error(w, "Failed to build SAML response", http.StatusInternalServerError)
					return
				}

				delete(samlSession.Values, "saml-context")
				_ = samlSession.Save(r, w)
				acsURL := samlContext.AssertionConsumerServiceURL
				if acsURL == "" {
					log.Error("Missing ACS URL in SAML context (login auto-redirect)")
					http.Error(w, "Invalid SAML context (ACS)", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>SAML Redirect</title></head><body onload="document.forms[0].submit()">`)
				_, _ = fmt.Fprintf(w, `<form method="post" action="%s">`, template.HTMLEscapeString(acsURL))
				_, _ = fmt.Fprintf(w, `<input type="hidden" name="SAMLResponse" value="%s"/>`, template.HTMLEscapeString(samlResp))
				if samlContext.RelayState != "" {
					_, _ = fmt.Fprintf(w, `<input type="hidden" name="RelayState" value="%s"/>`, template.HTMLEscapeString(samlContext.RelayState))
				}
				_, _ = fmt.Fprintf(w, `<noscript><p>JavaScript disabled. Click continue.</p><button type="submit">Continue</button></noscript></form></body></html>`)
				return
			}
		}
	}

	if samlContext == nil && isSAMLParam && data.UserSession.IsAuthenticated {
		if lastRaw, ok := samlSession.Values["last-saml"].(string); ok && lastRaw != "" {
			if lastCtx, err := models.DeserializeSAMLRequestContext(lastRaw); err == nil {

				if time.Since(lastCtx.RequestTimestamp) < 10*time.Minute {
					log.WithFields(log.Fields{"user": data.UserSession.Email, "sp": lastCtx.Issuer}).
						Info("Reissuing SAML response using cached last-saml context (back navigation)")
					if samlResp, buildErr := h.userService.BuildSAMLResponse(data.UserSession, *lastCtx); buildErr == nil {
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						_, _ = fmt.Fprintf(
							w,
							`<!DOCTYPE html><html><head><title>SAML Redirect</title></head><body onload="document.forms[0].submit()">`,
						)
						_, _ = fmt.Fprintf(
							w,
							`<form method="post" action="%s">`,
							template.HTMLEscapeString(lastCtx.AssertionConsumerServiceURL),
						)
						_, _ = fmt.Fprintf(
							w,
							`<input type="hidden" name="SAMLResponse" value="%s"/>`,
							template.HTMLEscapeString(samlResp),
						)
						if lastCtx.RelayState != "" {
							_, _ = fmt.Fprintf(
								w,
								`<input type="hidden" name="RelayState" value="%s"/>`,
								template.HTMLEscapeString(lastCtx.RelayState),
							)
						}
						_, _ = fmt.Fprintf(
							w,
							`<noscript><p>JavaScript disabled. Click continue.</p><button type="submit">Continue</button></noscript></form></body></html>`,
						)
						return
					} else {
						log.WithError(buildErr).Warn("Failed to build SAML response from last-saml context")
					}
				} else {
					log.WithField("age", time.Since(lastCtx.RequestTimestamp)).Info("Cached last-saml context expired; rendering login")
				}
			}
		}
	}

	h.renderLoginPage(w, data)
}

func (h *AuthHandler) validateLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	rememberMe := r.FormValue("remember_me") == "on"

	data := models.LoginPageData{
		PageData: models.PageData{
			Title: "Login - MyIDP",
			Page:  "login",
		},
		Email:    email,
		Remember: rememberMe,
	}

	if email == "" || password == "" {
		data.Error = "Missing required fields"
		h.renderLoginPage(w, data)
		return
	}

	if err := helpers.ValidateEmail(email); err != nil {
		data.Error = "Please enter a valid email address"
		h.renderLoginPage(w, data)
		return
	}

	user, authErr := h.userService.Authenticate(r.Context(), email, password)
	if authErr != nil {
		log.WithError(authErr).Errorf("Failed to validate login")
		data.Error = "Internal server error, please try again"
		h.renderLoginPage(w, data)
		return
	}
	if user == nil {
		data.Error = "Invalid email address or password"
		h.renderLoginPage(w, data)
		return
	}
	userSession := models.UserSession{
		UserID:          fmt.Sprintf("%d", user.ID),
		Username:        user.Username,
		Email:           user.Email,
		UserRoles:       user.UserRoles,
		IsAuthenticated: true,
		AuthMethod:      "password",
		AuthTimestamp:   time.Now(),
		SessionID:       uuid.New().String(),
		Status:          user.Status,
	}
	serializedUserSession, err := userSession.Serialize()
	if err != nil {
		log.WithError(err).Errorf("Failed to serialize user session")
		http.Error(w, "Session serialization error", http.StatusInternalServerError)
		return
	}
	sessionStore, err := session.Store.Get(r, "user-session")
	if err != nil {
		log.WithError(err).Error("Failed to get session")
	}
	sessionStore.Values["user-session"] = serializedUserSession
	sessionOptions := *session.Store.Options
	if rememberMe {
		sessionOptions.MaxAge = 7 * 24 * 60 * 60
	}
	sessionStore.Options = &sessionOptions
	if err := sessionStore.Save(r, w); err != nil {
		log.WithError(err).Error("Failed to save session")
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	samlSession, err := session.Store.Get(r, "saml-context")
	if err != nil {
		log.WithError(err).Error("Session store corruption detected during login validation")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var samlContext *models.SAMLRequestContext

	if contextStr, ok := samlSession.Values["saml-context"].(string); ok && contextStr != "" {
		samlContext, err = models.DeserializeSAMLRequestContext(contextStr)
		if err != nil {
			log.WithError(err).Error("Failed to deserialize SAML context - proceeding with direct login")
		} else {
			log.Debugf("SAML context found - SP: %s, RequestID: %s", samlContext.Issuer, samlContext.RequestID)
		}
	} else {
		log.Debug("No SAML context found in session - direct login flow")
	}

	if samlContext != nil {
		log.Infof("User %s authenticated successfully for SAML flow - SP: %s", user.Email, samlContext.Issuer)

		samlResp, buildErr := h.userService.BuildSAMLResponse(userSession, *samlContext)
		if buildErr != nil {
			log.WithError(buildErr).Error("Failed to build SAML response")
			http.Error(w, "Failed to build SAML response", http.StatusInternalServerError)
			return
		}
		acsURL := samlContext.AssertionConsumerServiceURL
		relayState := samlContext.RelayState
		if acsURL == "" {
			log.Error("Missing ACS URL in SAML context")
			http.Error(w, "Invalid SAML context (ACS)", http.StatusInternalServerError)
			return
		}

		if rawCtx, ok := samlSession.Values["saml-context"].(string); ok && rawCtx != "" {
			samlSession.Values["last-saml"] = rawCtx
		}

		delete(samlSession.Values, "saml-context")
		if err := samlSession.Save(r, w); err != nil {
			log.WithError(err).Warn("Failed to clear saml-context session")
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		_, _ = fmt.Fprintf(
			w,
			`<!DOCTYPE html><html><head><title>SAML Redirect</title></head><body onload="document.forms[0].submit()">`,
		)
		_, _ = fmt.Fprintf(w, `<form method="post" action="%s">`, template.HTMLEscapeString(acsURL))
		_, _ = fmt.Fprintf(
			w,
			`<input type="hidden" name="SAMLResponse" value="%s"/>`,
			template.HTMLEscapeString(samlResp),
		)
		if relayState != "" {
			_, _ = fmt.Fprintf(
				w,
				`<input type="hidden" name="RelayState" value="%s"/>`,
				template.HTMLEscapeString(relayState),
			)
		}
		_, _ = fmt.Fprintf(
			w,
			`<noscript><p>JavaScript disabled. Click continue.</p><button type="submit">Continue</button></noscript></form></body></html>`,
		)
		return
	}

	log.Infof("User %s authenticated successfully - direct login flow", user.Email)

	http.Error(w, "Direct login successful - dashboard redirect not implemented", http.StatusNotImplemented)
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getLoginForm(w, r)
	case http.MethodPost:
		h.validateLogin(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
