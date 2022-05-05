package auth

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// Claims is a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry
// time
type Claims struct {
	UID       string `json:"uid"`
	FirstName string `json:"first_name"`
	jwt.StandardClaims
}

type JWT struct {
	Token   string
	Expires time.Time
}

// createJWT creates a JWT with the user ID from the database as well as
// its firstname as claims
func createJWT(jwtSecret []byte, uid, firstname string) (JWT, error) {
	var j JWT
	var err error
	j.Expires = time.Now().Add(time.Hour)
	claims := Claims{
		UID:       uid,
		FirstName: firstname,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: j.Expires.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	j.Token, err = token.SignedString(jwtSecret)
	return j, err
}

// VerifyJWT returns true if a JWT is valid, false otherwise
func VerifyJWT(token string, jwtSecret []byte) (bool, error) {
	claims := &Claims{}
	j, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return false, nil
		}
		if strings.Contains(err.Error(), "token is expired") {
			return false, nil
		}
		return false, err
	}

	return j.Valid, nil
}

// GetJWTClaims returns claims associated to a JWT
func GetJWTClaims(token string, jwtSecret []byte) (Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	return *claims, err
}
