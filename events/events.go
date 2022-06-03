package events

import "strings"

type Event struct {
	City        string
	Address     string
	Date        string
	Time        string
	Description string
	Organizer   string
	Link        string
	MapLink     string
	ID          string
	CreatedBy   string
	Category    string
}

var Categories = []string{
	"Autre",
	"Culture 🎭",
	"Droits sociaux",
	"Écologie 🌍",
	"Gilets jaunes",
	"Immigration",
	"LGTBQIA+ 🏳‍🌈",
	"Pass sanitaire",
	"Police",
	"Retraites",
	"Services publics",
	"Ukraine 🇺🇦",
}

// formatCity formats the city in an universal way
func formatCity(city string) string {
	return strings.Title(city)
}
