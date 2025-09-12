package models

type PageData struct {
	Page     string
	Title    string
	SubTitle string
	Error    string
	Success  string
	// User info (optional)
	Email    string
	Username string
	Status   string
	Roles    []string
	AuthTime string
	EntityID string
}
