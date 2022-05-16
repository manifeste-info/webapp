package notifications

const (
	KindEdit   = "edit"
	KindCreate = "create"
)

type Notifier interface {
	Send(Payload) error
}

type Payload struct {
	EventID, UserID string
	EventDesc       string
	Kind            string
}
