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

type Slack struct {
	Webhook string
	Channel string
}

func (s Slack) Send(p notifications.Payload) error {
	webhookUrl := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookUrl == "" {
		return fmt.Errorf("cannot create slack notifier: slack webhook URL cannot be empty")
	}

	attachment := slack.Attachment{
		Color:         "good",
		Fallback:      "Un nouvel évènement a été créé",
		AuthorName:    "Manifeste.Info",
		AuthorSubname: "manifeste.info",
		AuthorLink:    "https://manifeste.info",
		Text:          "<!here> Un nouvel event a été créé",
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
