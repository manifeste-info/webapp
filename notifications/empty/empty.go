package empty

import "github.com/manifeste-info/webapp/notifications"

type Empty struct{}

// This method immediatly returns with nil
func (e Empty) SendNewEvent(p notifications.PayloadNewEvent) error {
	return nil
}

// This method immediatly returns with nil
func (e Empty) SendNewAccount(p notifications.PayloadNewAccount) error {
	return nil
}

// This method immediatly returns with nil
func (e Empty) SendNewReport(p notifications.PayloadNewReport) error {
	return nil
}
