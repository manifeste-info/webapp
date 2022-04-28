package config

import "os"

var UnderDevelopment bool

const DateTimeFormat = "02/01/2006 15:04"
const MinPasswordLen = 8

const SessionCookieName = "m_session_cookie"
const SessionCookieExpiry = 3600

// Custom error messages
const ErrEventDoesNotExist = "event does not exist"

// Mails
var MailDomain = os.Getenv("MAILGUN_SEND_DOMAIN")

const MailSender = "noreply@manifeste.info"
const MailValidationSubject = "Confirmation du compte"
