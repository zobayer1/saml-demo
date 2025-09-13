package handlers

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"

	"sp1/config"
	"sp1/internal/models"
)

type HomeHandler struct {
	cfg         *config.Config
	tmplHome    *template.Template
	tmplIndex   *template.Template
	tmplLogin   *template.Template
	idpCert     *x509.Certificate
	replayCache map[string]time.Time
	mu          sync.Mutex
}

func NewHomeHandler(cfg *config.Config) *HomeHandler {
	tmplHome := template.Must(template.ParseFiles(
		"internal/templates/base.html",
		"internal/templates/partials/home.html",
	))
	tmplIndex := template.Must(template.ParseFiles(
		"internal/templates/base.html",
		"internal/templates/partials/index.html",
	))
	tmplLogin := template.Must(template.ParseFiles(
		"internal/templates/base.html",
		"internal/templates/partials/login.html",
	))
	h := &HomeHandler{
		cfg:         cfg,
		tmplHome:    tmplHome,
		tmplIndex:   tmplIndex,
		tmplLogin:   tmplLogin,
		replayCache: make(map[string]time.Time),
	}
	if cert, err := loadIDPCert(cfg.IDPMetadata); err == nil {
		h.idpCert = cert
		log.Infof("Loaded IdP signing cert (SP1)")
	} else {
		log.WithError(err).Warn("Failed to load IdP metadata certificate - signature validation disabled")
	}
	return h
}

func loadIDPCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch se := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(se.Name.Local, "X509Certificate") {
				var certText string
				if err := dec.DecodeElement(&certText, &se); err != nil {
					return nil, err
				}
				certText = strings.TrimSpace(certText)
				clean := strings.Map(func(r rune) rune {
					if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
						return r
					}
					return -1
				}, certText)
				der, err := base64.StdEncoding.DecodeString(clean)
				if err != nil {
					return nil, fmt.Errorf("decode base64: %w", err)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("parse cert: %w", err)
				}
				return cert, nil
			}
		}
	}
	return nil, errors.New("no X509Certificate element found")
}

func (h *HomeHandler) HandleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	cookie, err := r.Cookie("sp1-auth")
	if err != nil {
		next := r.URL.Path
		if next == "" || !strings.HasPrefix(next, "/") {
			next = "/home"
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	var email, username, status, authTime string
	var roles []string
	raw := cookie.Value
	if strings.HasPrefix(raw, "j:") {
		b64 := strings.TrimPrefix(raw, "j:")
		if decodedBytes, err := base64.StdEncoding.DecodeString(b64); err == nil {
			var payload struct {
				Email    string   `json:"email"`
				Username string   `json:"username"`
				Status   string   `json:"status"`
				Roles    []string `json:"roles"`
				AuthTime string   `json:"auth_time"`
			}
			if jsonErr := json.Unmarshal(decodedBytes, &payload); jsonErr == nil {
				email = payload.Email
				username = payload.Username
				status = payload.Status
				roles = payload.Roles
				authTime = payload.AuthTime
			}
		}
	} else if unesc, err := url.QueryUnescape(raw); err == nil {
		email = unesc
	} else {
		email = raw
	}

	if len(roles) > 0 {
		roles = transformRolesForSP(roles, "sp1")
	}
	data := models.PageData{
		Page:          "home",
		Title:         "SP1 Home (Protected)",
		SubTitle:      "Authenticated via SAML",
		Email:         email,
		Username:      username,
		Status:        status,
		Roles:         roles,
		AuthTime:      authTime,
		EntityID:      h.cfg.EntityID,
		Authenticated: true,
	}
	if err := h.tmplHome.Execute(w, data); err != nil {
		log.WithError(err).Error("Failed to render home template")
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (h *HomeHandler) HandleIndex(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("sp1-auth")
	auth := err == nil
	data := models.PageData{
		Page:          "index",
		Title:         "Welcome to Alpha Service",
		SubTitle:      "Public landing page for SP1",
		EntityID:      h.cfg.EntityID,
		Authenticated: auth,
	}
	if err := h.tmplIndex.Execute(w, data); err != nil {
		log.WithError(err).Error("Failed to render index template")
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (h *HomeHandler) HandleACS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	redirectHome := func() { http.Redirect(w, r, "/home", http.StatusSeeOther) }
	redirectLogin := func() { http.Redirect(w, r, "/login?next=%2Fhome", http.StatusSeeOther) }

	if c, err := r.Cookie("sp1-auth"); err == nil && c.Value != "" {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			if rs := r.FormValue("RelayState"); rs != "" && strings.HasPrefix(rs, "/") {
				http.Redirect(w, r, rs, http.StatusSeeOther)
				return
			}
		}
		redirectHome()
		return
	}

	if r.Method != http.MethodPost {
		redirectLogin()
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectLogin()
		return
	}
	encoded := r.FormValue("SAMLResponse")
	if encoded == "" {
		redirectLogin()
		return
	}
	relayState := r.FormValue("RelayState")

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		redirectLogin()
		return
	}

	if h.idpCert != nil {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(decoded); err != nil {
			redirectLogin()
			return
		}
		store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{h.idpCert}}
		ctx := dsig.NewDefaultValidationContext(store)
		if _, err := ctx.Validate(doc.Root()); err != nil {
			redirectLogin()
			return
		}
		respID := doc.Root().SelectAttrValue("ID", "")
		inResp := doc.Root().SelectAttrValue("InResponseTo", "")
		if respID == "" {
			redirectLogin()
			return
		}
		if h.isReplay(respID) || (inResp != "" && h.isReplay(inResp)) {
			redirectHome()
			return
		}
		if assertionEl := doc.Root().FindElement(".//saml:Assertion"); assertionEl != nil {
			if aID := assertionEl.SelectAttrValue("ID", ""); aID != "" {
				if h.isReplay(aID) {
					redirectHome()
					return
				}
				h.markProcessed(aID)
			}
		}
		h.markProcessed(respID)
		if inResp != "" {
			h.markProcessed(inResp)
		}
	}

	doc2 := etree.NewDocument()
	if err := doc2.ReadFromBytes(decoded); err != nil {
		redirectLogin()
		return
	}
	assertionEl := findFirst(doc2.Root(), endsWith("Assertion"))
	if assertionEl == nil {
		redirectLogin()
		return
	}
	nameIDEl := findFirst(assertionEl, endsWith("NameID"))
	email := ""
	if nameIDEl != nil {
		email = strings.TrimSpace(nameIDEl.Text())
	}
	attrs := map[string][]string{}
	if attrStmt := findFirst(assertionEl, endsWith("AttributeStatement")); attrStmt != nil {
		for _, child := range attrStmt.ChildElements() {
			if !endsWith("Attribute")(child.Tag) {
				continue
			}
			name := child.SelectAttrValue("Name", "")
			if name == "" {
				continue
			}
			var vals []string
			for _, v := range child.ChildElements() {
				if endsWith("AttributeValue")(v.Tag) {
					val := strings.TrimSpace(v.Text())
					if val != "" {
						vals = append(vals, val)
					}
				}
			}
			if len(vals) > 0 {
				attrs[strings.ToLower(name)] = vals
			}
		}
	}
	if v, ok := attrs["email"]; ok && len(v) > 0 {
		email = v[0]
	}
	username := firstOr(attrs["username"], "")
	status := firstOr(attrs["status"], "")
	roles := transformRolesForSP(attrs["role"], "sp1")
	authInstant := ""
	if authnStmt := findFirst(assertionEl, endsWith("AuthnStatement")); authnStmt != nil {
		authInstant = authnStmt.SelectAttrValue("AuthnInstant", "")
	}
	if authInstant == "" {
		authInstant = time.Now().UTC().Format(time.RFC3339)
	}
	if email == "" {
		email = "unknown@example.com"
	}
	payload := struct {
		Email    string   `json:"email"`
		Username string   `json:"username"`
		Status   string   `json:"status"`
		Roles    []string `json:"roles"`
		AuthTime string   `json:"auth_time"`
	}{Email: email, Username: username, Status: status, Roles: roles, AuthTime: authInstant}
	jsonBytes, _ := json.Marshal(payload)
	http.SetCookie(w, &http.Cookie{
		Name:     "sp1-auth",
		Value:    "j:" + base64.StdEncoding.EncodeToString(jsonBytes),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(30 * time.Minute),
	})
	to := relayState
	if to == "" || !strings.HasPrefix(to, "/") {
		to = "/home"
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (h *HomeHandler) buildRedirectAuthnRequest(relayState string) (string, error) {
	id, err := randomID(16)
	if err != nil {
		return "", err
	}
	req := models.AuthnRequest{
		ID:                          id,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC().Format(time.RFC3339),
		Destination:                 h.cfg.IDPSSOURL,
		AssertionConsumerServiceURL: h.cfg.ACSURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Issuer:                      models.Issuer{Value: h.cfg.EntityID},
	}
	xmlBytes, err := xml.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal authn request: %w", err)
	}

	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	if _, err = w.Write(xmlBytes); err != nil {
		return "", fmt.Errorf("deflate: %w", err)
	}
	_ = w.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	values := url.Values{}
	values.Set("SAMLRequest", encoded)
	if relayState != "" {
		values.Set("RelayState", relayState)
	}
	return h.cfg.IDPSSOURL + "?" + values.Encode(), nil
}

func (h *HomeHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	var nameIDVal string
	if c, err := r.Cookie("sp1-auth"); err == nil {
		raw := c.Value
		if strings.HasPrefix(raw, "j:") {
			if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "j:")); err == nil {
				var payload struct {
					Email string `json:"email"`
				}
				_ = json.Unmarshal(b, &payload)
				nameIDVal = payload.Email
			}
		} else {
			nameIDVal = raw
		}
	}

	http.SetCookie(w, &http.Cookie{Name: "sp1-auth", Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1})

	if nameIDVal == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	sloURL, err := h.buildLogoutRedirect(nameIDVal, "demo-session-index", h.cfg.SLOReturnURL)
	if err != nil {
		log.WithError(err).Error("Failed to build LogoutRequest redirect")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	log.WithField("redirect", sloURL).Info("Initiating SP1 SLO")
	http.Redirect(w, r, sloURL, http.StatusFound)
}

func (h *HomeHandler) HandleSLOComplete(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *HomeHandler) buildLogoutRedirect(nameIDVal, sessIndex, relayReturn string) (string, error) {
	id, err := randomID(16)
	if err != nil {
		return "", err
	}
	lr := models.LogoutRequest{
		ID:           id,
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  h.cfg.IDPSLOURL,
		Issuer:       models.Issuer{Value: h.cfg.EntityID},
		NameID:       models.NameID{Value: nameIDVal},
		SessionIndex: &models.SessionIndex{Value: sessIndex},
	}
	xmlBytes, err := xml.Marshal(lr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	if _, err = zw.Write(xmlBytes); err != nil {
		return "", err
	}
	_ = zw.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	q := url.Values{}
	q.Set("SAMLRequest", encoded)
	if relayReturn != "" {
		q.Set("RelayState", relayReturn)
	}
	return h.cfg.IDPSLOURL + "?" + q.Encode(), nil
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("_%x", b), nil
}

func (h *HomeHandler) isReplay(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ts, ok := h.replayCache[id]; ok {
		if time.Since(ts) < 10*time.Minute {
			return true
		}
		delete(h.replayCache, id)
	}
	return false
}

func (h *HomeHandler) markProcessed(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.replayCache[id] = time.Now()
}

func (h *HomeHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("sp1-auth"); err == nil {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/home"
	}
	data := models.PageData{
		Page:          "login",
		Title:         "Login",
		SubTitle:      "Select an Identity Provider",
		EntityID:      h.cfg.EntityID,
		Authenticated: false,
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if err := h.tmplLogin.Execute(w, struct {
		models.PageData
		Next string
	}{PageData: data, Next: next}); err != nil {
		log.WithError(err).Error("Failed to render login template")
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (h *HomeHandler) HandleLoginStart(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("sp1-auth"); err == nil {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/home"
	}
	redirectURL, buildErr := h.buildRedirectAuthnRequest(next)
	if buildErr != nil {
		log.WithError(buildErr).Error("Failed to build SAML AuthnRequest redirect (login start)")
		http.Error(w, "Failed to initiate SSO", http.StatusInternalServerError)
		return
	}
	log.WithFields(log.Fields{"relay": next, "redirect": redirectURL}).Info("Initiating SAML login from /login/start")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func firstOr(arr []string, def string) string {
	if len(arr) > 0 && arr[0] != "" {
		return arr[0]
	}
	return def
}

func endsWith(suffix string) func(string) bool {
	return func(tag string) bool {
		return strings.HasSuffix(tag, suffix)
	}
}

func findFirst(el *etree.Element, match func(string) bool) *etree.Element {
	if el == nil {
		return nil
	}
	for _, c := range el.ChildElements() {
		if match(c.Tag) {
			return c
		}
		if d := findFirst(c, match); d != nil {
			return d
		}
	}
	return nil
}

func transformRolesForSP(raw []string, spPrefix string) []string {
	var spRoles []string
	var idpFallback []string
	seen := map[string]struct{}{}
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		parts := strings.SplitN(r, ":", 2)
		if len(parts) == 2 {
			pref, val := parts[0], parts[1]
			if pref == spPrefix && val != "" {
				if _, ok := seen[val]; !ok {
					spRoles = append(spRoles, val)
					seen[val] = struct{}{}
				}
			} else if pref == "idp" && val != "" {
				if _, ok := seen[val]; !ok {
					idpFallback = append(idpFallback, val)
				}
			}
		} else {
			if _, ok := seen[r]; !ok {
				spRoles = append(spRoles, r)
				seen[r] = struct{}{}
			}
		}
	}
	if len(spRoles) == 0 {
		for _, v := range idpFallback {
			if _, ok := seen[v]; !ok {
				spRoles = append(spRoles, v)
				seen[v] = struct{}{}
			}
		}
	}
	return spRoles
}
