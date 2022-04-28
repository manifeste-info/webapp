package config

var UnderDevelopment bool

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
