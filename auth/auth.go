package auth

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

// Authenticate receives an email and a password, compares the hash with the one
// in database. If they match, it creates a session token, stores it in the
// Sessions map and returns the sessionToken to the caller
func Authenticate(email, password string) (string, error) {
	hash, err := getHashedPassword(email)
	if err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", err
	}

	sessionToken := createSession(email)
	log.Printf("user %s logged in\n", email)
	return sessionToken, nil
}

// Disconnect deletes the session token from the sessions k/v store. It returns
// true if it works, false otherwise
func Disconnect(sessionToken string) bool {
	return removeSession(sessionToken)
}
