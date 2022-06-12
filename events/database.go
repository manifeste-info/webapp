package events

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/database"
	"github.com/manifeste-info/webapp/utils"
	log "github.com/sirupsen/logrus"
)

// Create creates a new event in the database. It also do some formatting
// operations on some values such as the date and time to convert them to a
// common and parsable format
func Create(city, addr, date, tiime, desc, org, link, uid, cat string) (string, error) { // todo: we should pass a struct here
	dt, err := time.Parse(config.DateTimeFormat, fmt.Sprintf("%s %s", date, tiime))
	if err != nil {
		return "", err
	}
	id := utils.CreateULID()
	log.Infof("created ULID '%s' for event '%s' in database before database insert", id, desc)

	_, err = database.DB.Query(`INSERT INTO events (id,city,address,date,description,organizer,link,created_by,num_of_reports,category) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,$9);`,
		id, formatCity(city), addr, dt, desc, org, link, uid, cat)
	return id, err
}

// GetEventsByCityOrdered retuns a list of events for a given city. Those events
// are ordered chronologically
func GetEventsByCityOrdered(city string) ([]Event, error) {
	rows, err := database.DB.Query(`SELECT id,city,date,address,description,organizer,link,category FROM events WHERE city=$1;`, city)
	if err != nil {
		return []Event{}, err
	}

	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.City, &event.Date, &event.Address, &event.Description, &event.Organizer, &event.Link, &event.Category); err != nil {
			return events, err
		}
		dateTmp, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			return events, err
		}
		// do not show past events except for the last 8 hours
		if time.Now().After(dateTmp.Add(time.Hour * 8)) {
			continue
		}
		event.Date = dateTmp.String()
		event.City = formatCity(event.City)
		event.MapLink = utils.CreateMapLinkFromAddr(event.Address, event.City)
		events = append(events, event)
	}

	var globErr error
	// sort the events by date
	sort.SliceStable(events, func(i, j int) bool {
		t1, err := time.Parse("2006-01-02 15:04:05 -0700 MST", events[i].Date)
		if err != nil {
			globErr = err
			return false
		}
		t2, err := time.Parse("2006-01-02 15:04:05 -0700 MST", events[j].Date)
		if err != nil {
			globErr = err
			return false
		}
		return t2.After(t1)
	})

	if globErr != nil {
		return events, err
	}

	// translate events dates to french
	for i := range events {
		dateTmp, err := time.Parse("2006-01-02 15:04:05 -0700 MST", events[i].Date)
		if err != nil {
			return events, err
		}
		events[i].Date = translateDaysMonthsToFrench(dateTmp.Format("Monday 02 January 2006 à 15:04"))
	}

	return events, nil
}

// GetCitiesWithEvents returns a slice of strings which contains cities that are
// in the database, meaning cities with future, present or past events
func GetCitiesWithEvents() ([]string, error) {
	rows, err := database.DB.Query(`SELECT city FROM events;`)
	if err != nil {
		return nil, err
	}

	type row struct {
		City string `db:"city"`
	}
	var cities []string

	for rows.Next() {
		var r row
		if err := rows.Scan(&r.City); err != nil {
			return nil, err
		}

		if r.City != "" {
			// avoid duplicatas
			if !utils.StringInSlice(r.City, cities) {
				cities = append(cities, r.City)
			}
		}
	}
	sort.Strings(cities)
	return cities, nil
}

// GetEventByID returns a single event from the database identified by
// its ID. We also need to specify if we want to translate the date in french
// or not
func GetEventByID(id string, translate bool) (Event, error) {
	rows, err := database.DB.Query(`SELECT id,city,date,address,description,organizer,link,created_by,category FROM events WHERE id=$1`, id)
	if err != nil {
		return Event{}, err
	}

	exists := rows.Next()
	if !exists {
		return Event{}, errors.New("event does not exist")
	}
	var event Event
	if err := rows.Scan(&event.ID, &event.City, &event.Date, &event.Address, &event.Description, &event.Organizer, &event.Link, &event.CreatedBy, &event.Category); err != nil {
		return Event{}, err
	}
	dateTmp, err := time.Parse(time.RFC3339, event.Date)
	if err != nil {
		return Event{}, err
	}

	event.Date = dateTmp.String()
	event.City = formatCity(event.City)
	event.MapLink = utils.CreateMapLinkFromAddr(event.Address, event.City)

	if translate {
		event.Date = translateDaysMonthsToFrench(dateTmp.Format("Monday 02 January 2006 à 15:04"))
	}
	return event, nil
}

// GetEventsByUserID returns a list of events created by a user, identified by
// its user ID, called 'created_by' in the database
func GetEventsByUserID(id string) ([]Event, error) {
	rows, err := database.DB.Query(`SELECT id,city,date,address,description,organizer,link FROM events WHERE created_by=$1;`, id)
	if err != nil {
		return []Event{}, err
	}

	var events []Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(&event.ID, &event.City, &event.Date, &event.Address, &event.Description, &event.Organizer, &event.Link); err != nil {
			return events, err
		}
		dateTmp, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			return events, err
		}
		// do not show past events except for the last 8 hours
		if time.Now().After(dateTmp.Add(time.Hour * 8)) {
			continue
		}
		event.Date = dateTmp.String()
		event.City = formatCity(event.City)
		event.MapLink = utils.CreateMapLinkFromAddr(event.Address, event.City)
		events = append(events, event)
	}

	var globErr error
	// sort the events by date
	sort.SliceStable(events, func(i, j int) bool {
		t1, err := time.Parse("2006-01-02 15:04:05 -0700 MST", events[i].Date)
		if err != nil {
			globErr = err
			return false
		}
		t2, err := time.Parse("2006-01-02 15:04:05 -0700 MST", events[j].Date)
		if err != nil {
			globErr = err
			return false
		}
		return t2.After(t1)
	})

	if globErr != nil {
		return events, err
	}

	// translate events dates to french
	for i := range events {
		dateTmp, err := time.Parse("2006-01-02 15:04:05 -0700 MST", events[i].Date)
		if err != nil {
			return events, err
		}
		events[i].Date = translateDaysMonthsToFrench(dateTmp.Format("Monday 02 January 2006 à 15:04"))
	}

	return events, nil
}

// Update updates an event based on its ID
func Update(id string, event Event) error {
	date, err := time.Parse("02/01/2006 15:04", event.Date+" "+event.Time)
	if err != nil {
		return err
	}
	city := formatCity(event.City)

	_, err = database.DB.Query(`UPDATE events SET (city,date,address,description,organizer,link,category) = ($1,$2,$3,$4,$5,$6,$7) WHERE id=$8`,
		city, date, event.Address, event.Description, event.Organizer, event.Link, event.Category, id)
	if err != nil {
		return err
	}
	return nil
}

// GetEventCreatorID returns the created_by field associated to an event id
func GetEventCreatorID(id string) (string, error) {
	type row struct {
		CreatedBy string `db:"created_by"`
	}
	rows, err := database.DB.Query(`SELECT created_by FROM events WHERE id=$1;`, id)
	if err != nil {
		return "", err
	}

	rows.Next()
	var r row
	if err := rows.Scan(&r.CreatedBy); err != nil {
		return "", err
	}

	if r.CreatedBy == "" {
		return "", errors.New("created_by field is empty")
	}

	return r.CreatedBy, nil
}

// Delete deletes an event from the database
func Delete(id string) error {
	_, err := database.DB.Query(`DELETE FROM events WHERE id=$1;`, id)
	if err != nil {
		return err
	}
	return nil
}

// GetNumOfEvents returns the total number of events in the database
func GetNumOfEvents() (int, error) {
	row := database.DB.QueryRow(`SELECT COUNT(*) FROM events;`)
	var i int
	if err := row.Scan(&i); err != nil {
		return i, err
	}

	return i, nil
}

// translateDaysMonthsToFrench translates a date formatted for humans into
// french
func translateDaysMonthsToFrench(date string) string {
	// the default format is: Friday 15 April 2022
	parts := strings.Split(date, " ")
	day := parts[0]
	month := parts[2]
	var translated string

	switch day {
	case "Monday":
		translated = strings.Replace(date, day, "Lundi", -1)
	case "Tuesday":
		translated = strings.Replace(date, day, "Mardi", -1)
	case "Wednesday":
		translated = strings.Replace(date, day, "Mercredi", -1)
	case "Thursday":
		translated = strings.Replace(date, day, "Jeudi", -1)
	case "Friday":
		translated = strings.Replace(date, day, "Vendredi", -1)
	case "Saturday":
		translated = strings.Replace(date, day, "Samedi", -1)
	case "Sunday":
		translated = strings.Replace(date, day, "Dimanche", -1)
	default:
		// WTF?
	}

	switch month {
	case "January":
		translated = strings.Replace(translated, month, "Janvier", -1)
	case "February":
		translated = strings.Replace(translated, month, "Février", -1)
	case "March":
		translated = strings.Replace(translated, month, "Mars", -1)
	case "April":
		translated = strings.Replace(translated, month, "Avril", -1)
	case "May":
		translated = strings.Replace(translated, month, "Mai", -1)
	case "June":
		translated = strings.Replace(translated, month, "Juin", -1)
	case "July":
		translated = strings.Replace(translated, month, "Juillet", -1)
	case "August":
		translated = strings.Replace(translated, month, "Août", -1)
	case "September":
		translated = strings.Replace(translated, month, "Septembre", -1)
	case "October":
		translated = strings.Replace(translated, month, "Octobre", -1)
	case "November":
		translated = strings.Replace(translated, month, "Novembre", -1)
	case "December":
		translated = strings.Replace(translated, month, "Décembre", -1)
	default:
		// hmmm...
	}

	return translated
}

// GetAllEvents returns all events in database
func GetAllEvents() ([]Event, error) {
	rows, err := database.DB.Query(`SELECT id,city,address,date,description,organizer,link,created_by FROM events;`)
	if err != nil {
		return nil, err
	}
	var es []Event

	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.City, &e.Address, &e.Date, &e.Description, &e.Organizer, &e.Link, &e.CreatedBy); err != nil {
			return nil, err
		}
		es = append(es, e)
	}
	return es, nil
}

// GetEventReports returns the number of reports for a single event
func GetEventReports(id string) (int, error) {
	row := database.DB.QueryRow(`SELECT num_of_reports FROM events WHERE id=$1;`, id)
	var i int
	if err := row.Scan(&i); err != nil {
		return i, err
	}
	return i, nil
}

// UpdateEventReports updates the number of reports an event has
func UpdateEventReports(id string, num int) error {
	_, err := database.DB.Query(`UPDATE events SET num_of_reports=$1 WHERE id=$2;`, num, id)
	return err
}

func GetCitiesWithFutureEvents() ([]string, error) {
	rows, err := database.DB.Query(`SELECT city, date FROM events;`)
	if err != nil {
		return nil, err
	}

	type row struct {
		City string `db:"city"`
		Date string `db:"date"`
	}
	var cities []string

	for rows.Next() {
		var r row
		if err := rows.Scan(&r.City, &r.Date); err != nil {
			return nil, err
		}

		if r.City != "" {
			dateTmp, err := time.Parse(time.RFC3339, r.Date)
			if err != nil {
				return cities, err
			}

			if time.Now().After(dateTmp.Add(time.Hour * 8)) {
				continue
			}

			// avoid duplicatas
			if !utils.StringInSlice(r.City, cities) {
				cities = append(cities, r.City)
			}
		}
	}
	sort.Strings(cities)
	return cities, nil
}
