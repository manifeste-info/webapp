package slack

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/manifeste-info/webapp/notifications"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

type Slack struct{}

func (s Slack) Send(p notifications.Payload) error {
	webhookUrl := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookUrl == "" {
		return fmt.Errorf("cannot create slack notifier: slack webhook URL cannot be empty")
	}

	var fb, txt string
	switch p.Kind {
	case notifications.KindCreate:
		fb = "Un nouvel évènement a été créé"
		txt = "<!here> Un nouvel event a été créé."
	case notifications.KindEdit:
		fb = "Un évènement a été édité"
		txt = "<!here> Un event a été édité."
	}
	attachment := slack.Attachment{
		Color:         "good",
		Fallback:      fb,
		AuthorName:    "Manifeste.Info",
		AuthorSubname: "manifeste.info",
		AuthorLink:    "https://manifeste.info",
		Text:          txt,
		Ts:            json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
	}

	attachment2 := slack.Attachment{
		Color: "good",
		Text:  fmt.Sprintf("Description: %s\n\nUserID: `%s`\n EventID: `%s`\nLien: `https://manifeste.info/evenement/%s`", p.EventDesc, p.UserID, p.EventID, p.EventID),
		Ts:    json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
	}

	msg := slack.WebhookMessage{
		Attachments: []slack.Attachment{attachment, attachment2},
	}

	logrus.Infof("sending slack payload with userID: %s, eventID: %s, event desc: %s", p.UserID, p.EventID, p.EventDesc)
	return slack.PostWebhook(webhookUrl, &msg)
}
