package mail

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/google/uuid"
	"github.com/manifeste-info/webapp/config"
	"gopkg.in/gomail.v2"
)

var d *gomail.Dialer
var e sesInfo

// the key is the token and the value is the email
var pendingValidtionTokens map[string]user

type user struct {
	email        string
	sessionToken string
}

type sesInfo struct {
	sender     string
	senderName string
	smtpUser   string
	smtpPass   string
	host       string
	port       int
}

// CreateInstance creates a new mail instance
func CreateInstance() error {
	port, err := strconv.Atoi(os.Getenv("SES_SMTP_PORT"))
	if err != nil {
		return err
	}
	e = sesInfo{
		sender:     config.MailSender,
		senderName: config.MailSenderName,
		smtpUser:   os.Getenv("SES_SMTP_USER"),
		smtpPass:   os.Getenv("SES_SMTP_PASS"),
		host:       os.Getenv("SES_SMTP_HOST"),
		port:       port,
	}
	d = gomail.NewDialer(e.host, e.port, e.smtpUser, e.smtpPass)
	pendingValidtionTokens = make(map[string]user)
	return nil
}

// SendConfirmationToken creates a confirmation token, adds it to a pending
// validation tokens map and sends a link to the user to activate its account
func SendConfirmationToken(email, sessionToken string) error {
	token := uuid.NewString()
	u := user{
		email:        email,
		sessionToken: sessionToken,
	}
	log.Printf("user '%s' has been attributed validation token '%s'\n", email, token)

	to := []string{email}
	m := gomail.NewMessage()
	m.SetBody("text/html", buildConfirmationBody(token))
	m.SetHeaders(map[string][]string{
		"From":    {m.FormatAddress(e.sender, e.senderName)},
		"To":      to,
		"Subject": {config.MailValidationSubject},
	})

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	log.Printf("sent confirmation email to '%s', validation token is '%s'\n", email, token)

	// add the token to the pendingValidationTokens map
	pendingValidtionTokens[token] = u
	return nil
}

// ValidateConfirmationToken checks if a confirmation token is valid. if yes, it
// returns true and delete the token from the pending validation map. It returns
// false otherwise
func ValidateConfirmationToken(token string) bool {
	u, ok := pendingValidtionTokens[token]
	if !ok {
		return false
	}

	log.Printf("user '%s' confirmed its account with token '%s'\n", u.email, token)
	delete(pendingValidtionTokens, token)
	return true
}

func buildConfirmationBody(token string) string {
	url := "https://manifeste.info/moncompte/confirmation/" + token
	return fmt.Sprintf(`Bonjour,
<br><br>
Voilà le lien pour valider ton adresse mail: <a href="%s">%s</a>.
<br><br>
À bientôt sur Manifeste.info !
`, url, url)
}
