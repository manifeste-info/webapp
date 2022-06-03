package notifications

const (
	KindEdit   = "edit"
	KindCreate = "create"
)

type Notifier interface {
	SendNewEvent(PayloadNewEvent) error
	SendNewAccount(PayloadNewAccount) error
	SendNewReport(PayloadNewReport) error
}

type PayloadNewEvent struct {
	EventID, UserID          string
	EventDesc, EventCategory string
	Kind                     string
}

type PayloadNewAccount struct {
	Email, UserID          string
	Firstname, Lastname    string
	AccountValidationToken string
}

type PayloadNewReport struct {
	EventID string
}
