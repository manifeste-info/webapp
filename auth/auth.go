package auth

import (
	"github.com/manifeste-info/webapp/users"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// Authenticate receives an email and a password, compares the hash with the one
// in database. If they match, it creates a session token, stores it in the
// Sessions map and returns the sessionToken to the caller
func Authenticate(email, password string, jwtSecret []byte) (JWT, error) {
	u, err := users.GetUserInfosFromEmail(email)
	if err != nil {
		return JWT{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(password)); err != nil {
		return JWT{}, err
	}

	jwt, err := createJWT(jwtSecret, u.ID, u.Nickname)
	if err != nil {
		return JWT{}, err
	}
	log.Infof("created JWT '%s' for user '%s', ID '%s'", jwt.Token, u.Email, u.ID)
	return jwt, nil
}
