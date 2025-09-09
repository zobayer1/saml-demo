package models

type PageData struct {
	Page     string
	Title    string
	SubTitle string
	Error    string
	Success  string
}

type RegPageData struct {
	PageData
	UserValidationResponse
	EmailValidationResponse
	PasswordValidationResponse
	Username string
	Email    string
}

type LoginPageData struct {
	PageData
	UserSession
	SAMLState
	Email    string
	Remember bool
}
