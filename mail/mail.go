package mail

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/users"
	"gopkg.in/gomail.v2"
)

var d *gomail.Dialer
var e sesInfo

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
	return nil
}

// SendConfirmationToken takes a validation token, adds it to a pending
// validation tokens map and sends a link to the user to activate its account
func SendConfirmationToken(email, sessionToken, vt string) error {
	log.Printf("user '%s' has been attributed validation token '%s'", email, vt)

	to := []string{email}
	m := gomail.NewMessage()
	m.SetBody("text/html", buildConfirmationBody(vt))
	m.SetHeaders(map[string][]string{
		"From":    {m.FormatAddress(e.sender, e.senderName)},
		"To":      to,
		"Subject": {config.MailValidationSubject},
	})

	if err := d.DialAndSend(m); err != nil {
		return err
	}

	log.Printf("sent confirmation email to '%s', validation token is '%s'", email, vt)
	return nil
}

// ValidateConfirmationToken checks if a confirmation token is valid. if yes, it
// returns true and delete the token from the pending validation map. It returns
// false otherwise
func ValidateConfirmationToken(uid, token string) (bool, error) {
	dbt, err := users.GetValidationToken(uid)
	if err != nil {
		return false, err
	}
	if dbt != token {
		return false, nil
	}

	log.Printf("user '%s' confirmed its account with token '%s'", uid, token)
	return true, nil
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
