package config

import (
	"os"
)

type Config struct {
	Notifier        string
	Env             string
	ReportThreshold string
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
func New() Config {
	var c Config
	c.Notifier = os.Getenv("MANIFESTE_NOTIFIER")
	c.Env = os.Getenv("GIN_MODE")
	if c.Env == "" {
		c.Env = "development"
	}
	c.ReportThreshold = os.Getenv("REPORTS_THRESHOLD")
	return c
}
