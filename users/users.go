package users

import "time"

type User struct {
	ID                     string    `db:"id"`
	Nickname               string    `db:"nick_name"`
	Email                  string    `db:"email"`
	IsAdmin                bool      `db:"is_admin"`
	HasConfirmedAccount    bool      `db:"has_confirmed_account"`
	HashedPassword         string    `db:"password_hash"`
	CreatedAt              time.Time `db:"created_at"`
	AccountValidationToken string    `db:"account_validation_token"`
}
