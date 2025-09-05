package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"idp/internal/helpers"
	"idp/internal/models"
	"idp/internal/services"
)

type AuthHandler struct {
	userService *services.UserService
}

func NewAuthHandler(userService *services.UserService) *AuthHandler {
	return &AuthHandler{userService: userService}
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.GetLoginForm(w, r)
	case http.MethodPost:
		h.ValidateLogin(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *AuthHandler) GetLoginForm(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "base.html"),
		filepath.Join("internal", "templates", "partials", "login.html"),
	))
	data := models.PageData{
		Title: "Login - MyIDP",
		Page:  "login",
		SSOState: models.SAMLState{
			SAMLFlow:   false,
			SPName:     "",
			SPEntityID: "",
		},
		CurrentUser: models.UserSession{
			IsAuthenticated: false,
		},
	}
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *AuthHandler) ValidateLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLoginWithError(w, r, "Invalid form data", "")
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")

	if email == "" {
		h.renderLoginWithError(w, r, "Email address is required", email)
		return
	}

	if password == "" {
		h.renderLoginWithError(w, r, "Password is required", email)
		return
	}

	if err := helpers.ValidateEmail(email); err != nil {
		h.renderLoginWithError(w, r, "Please enter a valid email address", email)
		return
	}

	user, authErr := h.userService.ValidateLogin(r.Context(), email, password)
	if authErr != nil {
		h.renderLoginWithError(w, r, authErr.Error(), email)
	}
	if user != nil {
		log.Infof("User %s authenticated successfully", user.Email)
	} else {
		h.renderLoginWithError(w, r, "Invalid email or password", email)
	}
	// 2. Database lookup and password verification
	// 3. Session management
	// 4. SAML flow handling
	// 5. Redirect handling

	http.Error(w, "Login validation completed - remaining steps not implemented", http.StatusNotImplemented)
}

func (h *AuthHandler) renderLoginWithError(w http.ResponseWriter, r *http.Request, errorMsg, email string) {
	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "base.html"),
		filepath.Join("internal", "templates", "partials", "login.html"),
	))
	data := models.PageData{
		Title: "Login - MyIDP",
		Page:  "login",
		Error: errorMsg,
		CurrentUser: models.UserSession{
			IsAuthenticated: false,
			Email:           email,
		},
		SSOState: models.SAMLState{
			SAMLFlow:   false,
			SPName:     "",
			SPEntityID: "",
		},
	}
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
