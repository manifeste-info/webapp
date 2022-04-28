package mail

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/mailgun/mailgun-go/v4"
	"github.com/manifeste-info/webapp/config"
)

var mg *mailgun.MailgunImpl

// the key is the token and the value is the email
var pendingValidtionTokens map[string]user

type user struct {
	email        string
	sessionToken string
}

// CreateInstance creates a new mailgun instance
func CreateInstance(apiKey string) {
	mg = mailgun.NewMailgun(config.MailDomain, apiKey)
	pendingValidtionTokens = make(map[string]user)
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

	// send the mail with a 10 sec timeout
	url := "https://manifeste.info/moncompte/confirmation/" + token
	body := fmt.Sprintf("Bonjour !\nVoilà le lien pour confirmer et terminer la création de ton compte Manifeste :\n\n%s\n\nÀ bientôt !\n\nL'équipe Manifeste.", url)
	msg := mg.NewMessage(config.MailSender, config.MailValidationSubject, body, email)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, id, err := mg.Send(ctx, msg)
	if err != nil {
		return err
	}
	log.Printf("sent confirmation email to '%s', email id is '%s', validation token is '%s'\n", email, id, token)

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
