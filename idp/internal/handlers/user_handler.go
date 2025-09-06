package handlers

import (
	"context"
	"html/template"
	"net/http"
	"path/filepath"
	"regexp"
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

func (h *UserHandler) renderRegisterPage(w http.ResponseWriter, data models.RegPageData) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "base.html"),
		filepath.Join("internal", "templates", "partials", "register.html"),
		filepath.Join("internal", "templates", "partials", "user_validation.html"),
		filepath.Join("internal", "templates", "partials", "email_validation.html"),
	))

	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.WithError(err).Error("Failed to render register template")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *UserHandler) getRegForm(w http.ResponseWriter, _ *http.Request) {
	data := models.RegPageData{
		PageData: models.PageData{
			Title: "Register - MyIDP",
			Page:  "register",
		},
		Username: "",
		Email:    "",
		UserValidationResponse: models.UserValidationResponse{
			ShowUserValidation: false,
		},
		EmailValidationResponse: models.EmailValidationResponse{
			ShowEmailValidation: false,
		},
	}
	h.renderRegisterPage(w, data)
}

func (h *UserHandler) submitReg(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	data := models.RegPageData{
		PageData: models.PageData{
			Title: "Register - MyIDP",
			Page:  "register",
		},
		Username: username,
		Email:    email,
		UserValidationResponse: models.UserValidationResponse{
			ShowUserValidation: true,
		},
		EmailValidationResponse: models.EmailValidationResponse{
			ShowEmailValidation: true,
		},
	}

	if username == "" || email == "" || password == "" || confirmPassword == "" {
		data.Error = "Missing required fields"
		h.renderRegisterPage(w, data)
		return
	}

	if err := helpers.ValidateUsername(username); err != nil {
		data.Error = "Username " + err.Error()
		data.UserValidationError = "Invalid user name"
		h.renderRegisterPage(w, data)
		return
	}

	if _, err := helpers.ValidatePassword(password); err != nil {
		data.Error = "Password " + err.Error()
		h.renderRegisterPage(w, data)
		return
	}

	if password != confirmPassword {
		data.Error = "Passwords do not match"
		h.renderRegisterPage(w, data)
		return
	}

	if err := helpers.ValidateEmail(email); err != nil {
		data.Error = "Email validation failed: " + err.Error()
		data.EmailValidationError = "Invalid email format"
		h.renderRegisterPage(w, data)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	exists, emailErr := h.userService.CheckEmailExists(ctx, email)
	if emailErr != nil {
		log.WithError(emailErr).Error("Failed to check email availability")
		data.Error = "Internal server error. Please try again."
		h.renderRegisterPage(w, data)
		return
	}
	if exists {
		data.Error = "An account with this email already exists"
		data.EmailValidationError = "Email is already registered"
		h.renderRegisterPage(w, data)
		return
	} else {
		data.EmailValidationSuccess = "Email is available"
	}

	user, err := h.userService.CreateUser(ctx, username, email, password)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			data.Error = "An account with this email already exists"
			data.EmailValidationError = "Email is already registered"
		} else {
			log.WithError(err).Error("Failed to create user")
			data.Error = "Registration failed. Please try again"
		}
		h.renderRegisterPage(w, data)
		return
	}

	data.Username = ""
	data.Email = ""
	data.ShowUserValidation = false
	data.ShowEmailValidation = false
	data.Success = "Registration successful! You can now log in"
	log.WithField("user_id", user.ID).WithField("email", email).Info("User registered successfully")

	h.renderRegisterPage(w, data)
}

func (h *UserHandler) HandleReg(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getRegForm(w, r)
	case http.MethodPost:
		h.submitReg(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *UserHandler) ValidateUsername(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	username := regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(r.FormValue("username")), " ")
	if username == "" {
		return
	}

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "partials", "user_validation.html"),
	))

	data := models.UserValidationResponse{ShowUserValidation: true}

	if err := helpers.ValidateUsername(username); err != nil {
		data.UserValidationError = "Invalid user name"
		tmplErr := tmpl.ExecuteTemplate(w, "user-validation-error", data)
		if tmplErr != nil {
			log.WithError(tmplErr).Error("Failed to render username validation template")
			http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	tmplErr := tmpl.ExecuteTemplate(w, "user-validation-success", data)
	if tmplErr != nil {
		log.WithError(tmplErr).Error("Failed to render username validation template")
		http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
	}
}

func (h *UserHandler) ValidateEmail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		return
	}

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "partials", "email_validation.html"),
	))

	data := models.EmailValidationResponse{ShowEmailValidation: true}

	if err := helpers.ValidateEmail(email); err != nil {
		data.EmailValidationError = "Invalid email format"
		tmplErr := tmpl.ExecuteTemplate(w, "email-validation-error", data)
		if tmplErr != nil {
			log.WithError(tmplErr).Error("Failed to render email validation template")
			http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	exists, err := h.userService.CheckEmailExists(ctx, email)
	if err != nil {
		log.WithError(err).Error("Failed to check email availability")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		data.EmailValidationError = "Email is already registered"
		tmplErr := tmpl.ExecuteTemplate(w, "email-validation-error", data)
		if tmplErr != nil {
			log.WithError(tmplErr).Error("Failed to render email validation template")
			http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	data.EmailValidationSuccess = "Email is available"
	tmplErr := tmpl.ExecuteTemplate(w, "email-validation-success", data)
	if tmplErr != nil {
		log.WithError(tmplErr).Error("Failed to render email validation template")
		http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
	}
}

func (h *UserHandler) ValidatePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		return
	}

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "partials", "passwd_validation.html"),
	))

	data := models.PasswordValidationResponse{ShowPasswordValidation: true}

	passwordScore, err := helpers.ValidatePassword(password)
	if err != nil {
		data.PasswordStrengthError = err.Error()
		tmplErr := tmpl.ExecuteTemplate(w, "password-strength-error", data)
		if tmplErr != nil {
			log.WithError(tmplErr).Error("Failed to render password validation template")
			http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	strengthText, strengthClass := helpers.GetPasswordStrengthLevel(passwordScore)
	data.PasswordStrengthSuccess = strengthText
	data.PasswordStrengthClass = "strength-" + strengthClass
	tmplErr := tmpl.ExecuteTemplate(w, "password-strength-success", data)
	if tmplErr != nil {
		log.WithError(tmplErr).Error("Failed to render password validation template")
		http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
	}
}

func (h *UserHandler) ValidatePasswordMatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	if confirmPassword == "" {
		return
	}

	tmpl := template.Must(template.ParseFiles(
		filepath.Join("internal", "templates", "partials", "passwd_validation.html"),
	))

	data := models.PasswordValidationResponse{ShowPasswordValidation: true}

	var tmplErr error
	if password != confirmPassword {
		data.PasswordMatchError = "Passwords do not match"
		tmplErr = tmpl.ExecuteTemplate(w, "password-match-error", data)
	} else {
		data.PasswordMatchSuccess = "Passwords match"
		tmplErr = tmpl.ExecuteTemplate(w, "password-match-success", data)
	}
	if tmplErr != nil {
		log.WithError(tmplErr).Error("Failed to render password match template")
		http.Error(w, tmplErr.Error(), http.StatusInternalServerError)
	}
}
