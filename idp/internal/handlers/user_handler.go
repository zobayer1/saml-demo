package handlers

import (
	"context"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"idp/internal/helpers"
	"idp/internal/models"
	"idp/internal/services"
)

type UserHandler struct {
	userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

func (h *UserHandler) HandleReg(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.GetRegForm(w, r)
	case http.MethodPost:
		h.SubmitReg(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *UserHandler) GetRegForm(w http.ResponseWriter, r *http.Request) {
	data := models.PageData{
		Title: "Register - MyIDP",
		Page:  "register",
	}
	h.renderRegisterPage(w, data, "", "")
}

func (h *UserHandler) SubmitReg(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.WithError(err).Error("Failed to parse registration form")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	data := models.PageData{
		Title: "Register - MyIDP",
		Page:  "register",
	}

	if username == "" || email == "" || password == "" || confirmPassword == "" {
		data.Error = "Missing required fields"
		h.renderRegisterPage(w, data, username, email)
		return
	}

	if err := helpers.ValidateEmail(email); err != nil {
		data.Error = "Email validation failed: " + err.Error()
		h.renderRegisterPage(w, data, username, email)
		return
	}

	_, err := helpers.ValidatePassword(password)
	if err != nil {
		data.Error = "Password validation failed: " + err.Error()
		h.renderRegisterPage(w, data, username, email)
		return
	}

	if password != confirmPassword {
		data.Error = "Passwords do not match"
		h.renderRegisterPage(w, data, username, email)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	user, err := h.userService.CreateUser(ctx, username, email, password)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			data.Error = "An account with this email already exists"
		} else {
			log.WithError(err).Error("Failed to create user")
			data.Error = "Registration failed. Please try again."
		}
		h.renderRegisterPage(w, data, username, email)
		return
	}

	data.Success = "Registration successful! Your account has been created. " +
		"You can now <a href=\"/login\" class=\"auth-link\">sign in</a> to access your account."
	log.WithField("user_id", user.ID).WithField("email", email).Info("User registered successfully")

	h.renderRegisterPage(w, data, "", "")
}

func (h *UserHandler) renderRegisterPage(w http.ResponseWriter, data models.PageData, username, email string) {
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"renderEmailValidation": func(email string) template.HTML {
			if email == "" {
				return ""
			}

			emailTmpl := template.Must(template.ParseFiles(
				filepath.Join("internal", "templates", "partials", "email_validation.html"),
			))

			var buf strings.Builder

			// First check email format
			if err := helpers.ValidateEmail(email); err != nil {
				data := struct{ Error string }{Error: "Invalid email format"}
				emailTmpl.ExecuteTemplate(&buf, "email-validation-error", data)
				return template.HTML(buf.String())
			}

			// Then check email availability
			ctx := context.Background()
			exists, err := h.userService.CheckEmailExists(ctx, email)
			if err != nil {
				data := struct{ Error string }{Error: "Unable to verify email availability"}
				emailTmpl.ExecuteTemplate(&buf, "email-validation-error", data)
				return template.HTML(buf.String())
			}

			if exists {
				data := struct{ Error string }{Error: "Email is already registered"}
				emailTmpl.ExecuteTemplate(&buf, "email-validation-error", data)
				return template.HTML(buf.String())
			}

			data := struct{ Success string }{Success: "Email is available"}
			emailTmpl.ExecuteTemplate(&buf, "email-validation-success", data)
			return template.HTML(buf.String())
		},
	}).ParseFiles(
		filepath.Join("internal", "templates", "base.html"),
		filepath.Join("internal", "templates", "partials", "register.html"),
	))

	combinedData := models.RegPageData{
		PageData: data,
		Username: username,
		Email:    email,
	}

	if err := tmpl.ExecuteTemplate(w, "base.html", combinedData); err != nil {
		log.WithError(err).Error("Failed to render register template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *UserHandler) ValidateEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "partials", "email_validation.html"),
	))

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	// First check email format
	if err := helpers.ValidateEmail(email); err != nil {
		data := struct{ Error string }{Error: "Invalid email format"}
		tmplErr := tmpl.ExecuteTemplate(w, "email-validation-error", data)
		if tmplErr != nil {
			http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Then check email availability
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	exists, err := h.userService.CheckEmailExists(ctx, email)
	if err != nil {
		log.WithError(err).Error("Failed to check email availability")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		data := struct{ Error string }{Error: "Email is already registered"}
		tmplErr := tmpl.ExecuteTemplate(w, "email-validation-error", data)
		if tmplErr != nil {
			http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	data := struct{ Success string }{Success: "Email is available"}
	tmplErr := tmpl.ExecuteTemplate(w, "email-validation-success", data)
	if tmplErr != nil {
		http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
	}
}

func (h *UserHandler) ValidatePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "partials", "passwd_validation.html"),
	))

	passwordScore, err := helpers.ValidatePassword(password)
	if err != nil {
		data := struct{ Error string }{Error: err.Error()}
		tmplErr := tmpl.ExecuteTemplate(w, "password-strength-error", data)
		if tmplErr != nil {
			http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	data := struct {
		Strength string
		Score    float64
	}{
		Strength: helpers.GetPasswordStrengthLevel(passwordScore),
		Score:    passwordScore,
	}
	tmplErr := tmpl.ExecuteTemplate(w, "password-strength-success", data)
	if tmplErr != nil {
		http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
	}
}

func (h *UserHandler) ValidatePasswordMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if confirmPassword == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "partials", "passwd_validation.html"),
	))

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	var tmplErr error
	if password != confirmPassword {
		data := struct{ Error string }{Error: "Passwords do not match"}
		tmplErr = tmpl.ExecuteTemplate(w, "password-match-error", data)
	} else {
		data := struct{ Success string }{Success: "Passwords match"}
		tmplErr = tmpl.ExecuteTemplate(w, "password-match-success", data)
	}
	if tmplErr != nil {
		http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
	}
}
