package users

import (
	"log"

	"github.com/manifeste-info/webapp/auth"
	"github.com/manifeste-info/webapp/database"
)

// CreateAccount creates a new account in the database
func CreateAccount(firstname, lastname, email, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	log.Println("hashed password, adding user to database")
	return add(firstname, lastname, email, hash)
}

// add adds a user in the database
func add(firstname, lastname, email, hash string) error {
	_, err := database.DB.Query(`INSERT INTO users (id, email, first_name, last_name, password_hash, is_admin, has_confirmed_account) values (1000000000000*random(), $1, $2, $3, $4, false, false);`,
		email, firstname, lastname, hash)
	return err
}

// CheckIfExists checks if a user already exists in the database
func CheckIfExists(email string) (bool, error) {
	row := database.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email=$1;`, email)

	var i int
	if err := row.Scan(&i); err != nil {
		return false, err
	}
	return i != 0, nil
}

// GetUserInfos retrieve a firstname, a lastname, an email and an user ID based
// on a session token
func GetUserInfos(sessionToken string) (string, string, string, error) {
	type user struct {
		FirstName string `db:"first_name"`
		LastName  string `db:"last_name"`
	}
	var u user

	email := auth.GetEmailFromSessionToken(sessionToken)

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

	email := auth.GetEmailFromSessionToken(sessionToken)

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
