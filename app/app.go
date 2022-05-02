package app

import (
	"fmt"

	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/notifications"
	"github.com/manifeste-info/webapp/notifications/empty"
	"github.com/manifeste-info/webapp/notifications/slack"
)

type App struct {
	Notifier    notifications.Notifier
	Environment string
}

// New returns a newly configured App
func New(c config.Config) (App, error) {
	var a App

	switch c.Notifier {
	case "", "empty":
		a.Notifier = empty.Empty{}
	case "slack":
		a.Notifier = slack.Slack{}
	default:
		return App{}, fmt.Errorf("notifier %s is not supported", c.Notifier)
	}

	if c.Env == "release" {
		a.Environment = "production"
	}

	return a, nil
}
