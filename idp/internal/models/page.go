package models

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
	Username               string
	Email                  string
	EmailValidationError   string // For email format/availability errors
	EmailValidationSuccess string // For email availability success message
	ShowEmailValidation    bool   // Whether to show email validation feedback
}

type LoginPageData struct {
	PageData
	Email string
}
