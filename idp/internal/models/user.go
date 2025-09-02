package models

import (
	"time"
)

type User struct {
	ID        int
	Email     string
	Username  string
	CreatedAt time.Time
	Status    string
}

type UserSession struct {
	UserID          string    // Unique user identifier
	Username        string    // User login name
	Email           string    // User email
	UserRoles       []string  // Roles assigned to user
	IsAuthenticated bool      // Authentication status
	AuthMethod      string    // "password", "mfa", etc.
	AuthTimestamp   time.Time // When user authenticated
	SessionID       string    // Unique session identifier
	Status          string    // "active", "inactive", etc.
}

type SessionMetadata struct {
	SessionID string    // Unique session ID
	CreatedAt time.Time // Session creation time
	ExpiresAt time.Time // Session expiration
	IPAddress string    // Client IP
	UserAgent string    // Client user agent
	CSRFToken string    // CSRF protection
}
