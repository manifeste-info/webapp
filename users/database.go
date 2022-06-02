package users

import (
	"fmt"
	"strings"

	"github.com/manifeste-info/webapp/database"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// CreateAccount creates a new account in the database
func CreateAccount(firstname, lastname, email, password, vt, id string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	log.Infof("hashed '%s' password, adding user to database", email)
	return add(firstname, lastname, email, hash, vt, id)
}

// add adds a user in the database
func add(firstname, lastname, email, hash, vt, id string) error {
	log.Infof("created ULID '%s' for user '%s' in database before database insert", id, email)
	_, err := database.DB.Query(`INSERT INTO users (id, email, first_name, last_name, password_hash, is_admin, has_confirmed_account, account_validation_token) values ($1, $2, $3, $4, $5, false, false, $6);`,
		id, email, firstname, lastname, hash, vt)
	return err
}

// CheckIfExists checks if a user already exists in the database. It detects if
// the emails contains a +. If it is the case and if the fixed part is already
// present, it returns false
func CheckIfExists(email string) (bool, error) {
	// split the email address in two: local and domain
	parts := strings.Split(email, "@")
	local, domain := parts[0], parts[1]

	// split the local part in two and keep the fixed part
	var fixed, pattern string
	if strings.Contains(local, "+") {
		localparts := strings.Split(local, "+")
		fixed = localparts[0]
		pattern = fixed + "%@" + domain
	} else {
		pattern = local + "%@" + domain
	}

	row := database.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email LIKE $1;`, pattern)

	var i int
	if err := row.Scan(&i); err != nil {
		return false, err
	}
	return i != 0, nil
}

// GetUserInfosFromSessionToken retrieve a firstname, a lastname, an email and an user ID based
// on a session token
func GetUserInfosFromSessionToken(sessionToken string) (string, string, string, error) {
	type user struct {
		FirstName string `db:"first_name"`
		LastName  string `db:"last_name"`
	}
	var u user
	log.Infof("getting user informations for session token: '%s'", sessionToken)
	// email := auth.GetEmailFromSessionToken(sessionToken)
	email := "broken"
	log.Infof("retrieved email '%s' associated with token '%s'", email, sessionToken)

	if email == "" {
		return "", "", "", fmt.Errorf("error getting user infos for session token '%s': email address is empty", sessionToken)
	}

	rows, err := database.DB.Query(`SELECT first_name,last_name FROM users WHERE email=$1;`, email)
	if err != nil {
		return "", "", "", err
	}
	rows.Next()
	if err := rows.Scan(&u.FirstName, &u.LastName); err != nil {
		return "", "", "", err
	}
	return u.FirstName, u.LastName, email, nil
}

// GetUserID returns a user ID based on its email
func GetUserID(sessionToken string) (string, error) {
	type user struct {
		ID string `db:"id"`
	}
	var u user

	// email := auth.GetEmailFromSessionToken(sessionToken)
	email := "broken"

	rows, err := database.DB.Query(`SELECT id FROM users WHERE email=$1;`, email)
	if err != nil {
		return "", err
	}
	rows.Next()
	if err := rows.Scan(&u.ID); err != nil {
		return "", err
	}
	return u.ID, nil
}

// IsAdmin checks if the user is marked as admin in the database
func IsAdmin(id string) (bool, error) {
	type row struct {
		IsAdmin bool `db:"is_admin"`
	}

	rows, err := database.DB.Query(`SELECT is_admin FROM users WHERE id=$1;`, id)
	if err != nil {
		return false, err
	}

	rows.Next()
	var r row
	if err := rows.Scan(&r.IsAdmin); err != nil {
		return false, err
	}

	return r.IsAdmin, nil
}

// GetNumOfUsers returns the total number of users in the database
func GetNumOfUsers() (int, error) {
	row := database.DB.QueryRow(`SELECT COUNT(*) FROM users;`)
	var i int
	if err := row.Scan(&i); err != nil {
		return i, err
	}

	return i, nil
}

// GetNumOfBannedUsers returns the total number of users in the database
func GetNumOfBannedUsers() (int, error) {
	row := database.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE password_hash='banned';`)
	var i int
	if err := row.Scan(&i); err != nil {
		return i, err
	}

	return i, nil
}

// Ban bans a user by changing its password hash to "banned"
// todo: expire user's session token
func Ban(id string) error {
	_, err := database.DB.Query(`UPDATE users SET password_hash=$2 WHERE id=$1;`, id, "banned")
	return err
}

// HasConfirmedAccount returns true if the user account is confirmed, false
// otherwise. It also returns an error in case of failure
func HasConfirmedAccount(id string) (bool, error) {
	row := database.DB.QueryRow(`SELECT has_confirmed_account FROM users WHERE id=$1;`, id)
	var b bool
	if err := row.Scan(&b); err != nil {
		return false, err
	}
	return b, nil
}

// ValidateAccount validates a user account based in its userId
func ValidateAccount(id string) error {
	_, err := database.DB.Query(`UPDATE users SET has_confirmed_account='true' WHERE id=$1;`, id)
	return err
}

// GetUserInfosFromEmail returns the informations linked to a given email
// address
func GetUserInfosFromEmail(email string) (User, error) {
	var u User
	row := database.DB.QueryRow(`SELECT id,first_name,last_name,email,password_hash,is_admin,has_confirmed_account,created_at FROM users WHERE email=$1;`, email)
	if err := row.Scan(&u.ID, &u.Firstname, &u.Lastname, &u.Email, &u.HashedPassword, &u.IsAdmin, &u.HasConfirmedAccount, &u.CreatedAt); err != nil {
		return User{}, err
	}
	return u, nil
}

// hashPassword hashes a password using bcrypt with max cost and returns the
// hash
func hashPassword(pass string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// GetValidationToken returns an account validation token associated to
// a UID in database
func GetValidationToken(uid string) (string, error) {
	var token string
	row := database.DB.QueryRow(`SELECT account_validation_token FROM users WHERE id=$1;`, uid)
	if err := row.Scan(&token); err != nil {
		return token, err
	}
	return token, nil
}

// GetAllUsers returns all users present in database
func GetAllUsers() ([]User, error) {
	rows, err := database.DB.Query(`SELECT id,email,first_name,last_name,is_admin,has_confirmed_account,created_at,account_validation_token FROM users;`)
	if err != nil {
		return nil, err
	}
	var us []User

	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Firstname, &u.Lastname, &u.IsAdmin, &u.HasConfirmedAccount, &u.CreatedAt, &u.AccountValidationToken); err != nil {
			return nil, err
		}
		us = append(us, u)
	}
	return us, nil
}
