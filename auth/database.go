package auth

import (
	"github.com/manifeste-info/webapp/database"
)

// getHashedPassword retrieves a hashed password linked to an email address
func getHashedPassword(email string) (string, error) {
	type row struct {
		Hash string `db:"password_hash"`
	}

	rows, err := database.DB.Query(`SELECT password_hash FROM users WHERE email=$1;`, email)
	if err != nil {
		return "", err
	}

	rows.Next()
	var r row
	if err := rows.Scan(&r.Hash); err != nil {
		return "", err
	}
	return r.Hash, nil
}
