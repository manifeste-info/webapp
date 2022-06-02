package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

var DB *sql.DB

// NewConnection creates a *sql.DB. It also verifies that the
// database is reachable.
func NewConnection(host, port, user, pass, name string) error {
	var err error
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, pass, name)
	DB, err = sql.Open("postgres", dsn)
	if err != nil {
		return err
	}

	if err := DB.Ping(); err != nil {
		return err
	}
	log.Printf("database initialised")
	return nil
}
