package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Notifier string
	Env      string
}

const DateTimeFormat = "02/01/2006 15:04"
const MinPasswordLen = 8

const SessionCookieName = "m_session_cookie"
const SessionCookieExpiry = 3600

// Custom error messages
const ErrEventDoesNotExist = "event does not exist"

// Mails
const MailSender = "noreply@manifeste.info"
const MailSenderName = "Ne pas répondre"
const MailValidationSubject = "Confirmation de l'adresse mail"

// New returns a new Config
func New() (Config, error) {
	if err := godotenv.Load(); err != nil {
		return Config{}, err
	}
	var c Config

	c.Notifier = os.Getenv("MANIFESTE_NOTIFIER")
	c.Env = os.Getenv("GIN_MODE")
	return c, nil
}
