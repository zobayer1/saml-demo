package models

type UserValidationResponse struct {
	UserValidationError   string
	UserValidationSuccess string
	ShowUserValidation    bool
}

type EmailValidationResponse struct {
	EmailValidationError   string
	EmailValidationSuccess string
	ShowEmailValidation    bool
}

type PasswordValidationResponse struct {
	PasswordStrengthClass   string
	PasswordStrengthError   string
	PasswordStrengthSuccess string
	PasswordMatchError      string
	PasswordMatchSuccess    string
	ShowPasswordValidation  bool
}

type PageData struct {
	Page        string
	Title       string
	SubTitle    string
	CurrentUser UserSession
	SSOState    SAMLState
	Error       string
	Success     string
}

type RegPageData struct {
	PageData
	Username string
	Email    string
	UserValidationResponse
	EmailValidationResponse
	PasswordValidationResponse
}

type LoginPageData struct {
	PageData
	Email string
}
