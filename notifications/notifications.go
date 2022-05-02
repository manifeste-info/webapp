package notifications

type Notifier interface {
	Send(Payload) error
}

type Payload struct {
	EventID, UserID string
	EventDesc       string
}
