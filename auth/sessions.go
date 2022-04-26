package auth

import (
	"time"

	"github.com/google/uuid"
	"github.com/manifeste-info/webapp/config"
)

var Sessions = map[string]Session{}

type Session struct {
	Email  string
	Expiry time.Time
}

// IsExpired checks if a session is expired or not
func (s Session) IsExpired() bool {
	return s.Expiry.Before(time.Now())
}

// createSession creates a session for a user and returns the sessionToken
func createSession(email string) string {
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(config.SessionCookieExpiry * time.Second)

	Sessions[sessionToken] = Session{
		Email:  email,
		Expiry: expiresAt,
	}

	return sessionToken
}

// IsAuthenticated returns true if the session exists in the map and did not
// expirate, false otherwise
func IsAuthenticated(sessionToken string) bool {
	s, ok := Sessions[sessionToken]
	if !ok {
		return false
	}

	// expired == not authenticated
	// not expired == authenticated
	return !s.IsExpired()
}

// GetEmailFromSessionToken retrieves an email from a session token
func GetEmailFromSessionToken(sessionToken string) string {
	return Sessions[sessionToken].Email
}

// removeSession returns false if the session token does not exist, deletes it
// from the sesions k/v store and returns true otherwise
func removeSession(sessionToken string) bool {
	if _, ok := Sessions[sessionToken]; !ok {
		return false
	}
	delete(Sessions, sessionToken)
	return true
}
