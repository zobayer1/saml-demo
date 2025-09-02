package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"

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
	http.Error(w, "Not Implemented", http.StatusNotImplemented)
}
