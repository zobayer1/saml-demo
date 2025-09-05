package models

type EmailValidationResponse struct {
	EmailValidationError   string
	EmailValidationSuccess string
	ShowEmailValidation    bool
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
	EmailValidationResponse
}

type LoginPageData struct {
	PageData
	Email string
}
