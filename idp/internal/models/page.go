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
	EmailValidationError   string
	EmailValidationSuccess string
	ShowEmailValidation    bool
}

type LoginPageData struct {
	PageData
	Email string
}
