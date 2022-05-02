package slack

import (
	"fmt"
	"os"

	sl "github.com/ashwanthkumar/slack-go-webhook"
	"github.com/manifeste-info/webapp/notifications"
	"github.com/sirupsen/logrus"
)

type Slack struct {
	Webhook string
	Channel string
}

func (s Slack) Send(p notifications.Payload) error {
	webhookUrl := os.Getenv("SLACK_WEBHOOK_URL")
	channel := os.Getenv("SLACK_CHANNEL")
	if webhookUrl == "" || channel == "" {
		return fmt.Errorf("cannot create slack notifier: slack webhook URL or slack channel cannot be empty")
	}

	if channel[0] != '#' {
		channel = "#" + channel
	}

	logrus.Infof("preparing slack payload with userID: %s, eventID: %s, event desc: %s", p.UserID, p.EventID, p.EventDesc)
	attach := sl.Attachment{}
	attach.AddField(sl.Field{Title: "EventID", Value: p.EventID}).
		AddField(sl.Field{Title: "UserID", Value: p.UserID}).
		AddField(sl.Field{Title: "Description", Value: p.EventDesc})
	attach.AddAction(sl.Action{Type: "button", Text: "Voir", Url: "https://manifeste.info/evenement/" + p.EventID, Style: "primary"})
	payload := sl.Payload{
		Text:        "Un nouvel évènement a été créé.",
		Username:    "Manifeste.info",
		Channel:     channel,
		Attachments: []sl.Attachment{attach},
	}

	logrus.Infof("sending slack payload with userID: %s, eventID: %s, event desc: %s", p.UserID, p.EventID, p.EventDesc)
	err := sl.Send(webhookUrl, "", payload)
	if len(err) > 0 {
		return err[0] // todo: we might miss some errors, find a way to create a single error or return a slice
	}
	return nil
}
