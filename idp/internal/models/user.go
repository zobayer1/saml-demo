package models

import (
	"encoding/json"
	"time"
)

type User struct {
	ID        int
	Email     string
	Username  string
	CreatedAt time.Time
	Status    string
	UserRoles map[string]string
}

type UserSession struct {
	UserID          string            // Unique user identifier
	Username        string            // User login name
	Email           string            // User email
	UserRoles       map[string]string // Roles assigned to user
	IsAuthenticated bool              // Authentication status
	AuthMethod      string            // "password", "mfa", etc.
	AuthTimestamp   time.Time         // When user authenticated
	SessionID       string            // Unique session identifier
	Status          string            // "active", "inactive", etc.
}

type SessionMetadata struct {
	SessionID string    // Unique session ID
	CreatedAt time.Time // Session creation time
	ExpiresAt time.Time // Session expiration
	IPAddress string    // Client IP
	UserAgent string    // Client user agent
	CSRFToken string    // CSRF protection
}

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

func (u *UserSession) Serialize() (string, error) {
	data, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DeserializeUserSession converts JSON string back into a UserSession struct
func DeserializeUserSession(data string) (*UserSession, error) {
	var us UserSession
	if err := json.Unmarshal([]byte(data), &us); err != nil {
		return nil, err
	}
	return &us, nil
}
