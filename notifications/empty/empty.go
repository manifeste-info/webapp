package empty

import "github.com/manifeste-info/webapp/notifications"

type Empty struct{}

// This method immediatly returns with nil
func (e Empty) Send(p notifications.Payload) error {
	return nil
}
