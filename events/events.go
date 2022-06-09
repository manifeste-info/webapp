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

// formatCity formats the city in an universal way
func formatCity(city string) string {
	return strings.Title(city)
}

func GetAllCategories() []string {
	return []string{
		"Autre",
		"Culture 🎭",
		"Droits sociaux",
		"Écologie 🌍",
		"Féminismes",
		"Gilets jaunes",
		"Immigration",
		"Justice ⚖",
		"LGTBQIA+ 🏳‍🌈",
		"Pass sanitaire",
		"Police",
		"Politique",
		"Retraites",
		"Services publics",
		"Ukraine 🇺🇦",
	}
}
