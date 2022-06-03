package utils

import (
	"bufio"
	mathrand "math/rand"
	"os"
	"strings"
	"time"

	"github.com/agnivade/levenshtein"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"
)

var AllCities []string

// CreateMapLinkFromAddr creates a link to Google Maps, built with the address
// and the city provided
func CreateMapLinkFromAddr(addr, city string) string {
	prefix := "https://www.google.com/maps/place/"
	suffix := strings.ReplaceAll(addr+" "+city, " ", "+")
	return prefix + suffix
}

// StringInSlice returns `true` if s is in sl, `false` otherwise
func StringInSlice(s string, sl []string) bool {
	for _, v := range sl {
		if s == v {
			return true
		}
	}
	return false
}

// CreateULID returns a ULID string for database IDs
func CreateULID() string {
	seed := time.Now().UnixNano()
	source := mathrand.NewSource(seed)
	entropy := mathrand.New(source)
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}

// GetClosestCityName uses Levenstein distance to find the closest "official"
// city name. This allows us to correct some mispellings.
// Currently, the list of all the cities is stored in loaded from a file and
// is stored in memory.
func GetClosestCityName(name string) string {
	var closest, bestdist int
	for i, c := range AllCities {
		if bestdist == 0 {
			// first loop, initialise everything
			bestdist = levenshtein.ComputeDistance(name, c)
			closest = i
			continue
		}

		newdist := levenshtein.ComputeDistance(name, c)
		if newdist < bestdist {
			bestdist = newdist
			closest = i
		}
	}

	// if the best leventshtein distance is higher than 4, we consider that
	// the city is not in our database, the user is right.
	if bestdist > 4 {
		return name
	}
	return AllCities[closest]
}

// RemoveFromSliceOrdered removes a string from a slice and keep the order
func RemoveFromSliceOrdered(slice []string, s string) []string {
	sl := slice
	var idx int
	for i, v := range sl {
		if v == s {
			idx = i
		}
	}
	return append(sl[:idx], sl[idx+1:]...)
}

// this init function reads and loads the file containing all the cities.
func init() {
	fd, err := os.Open("cities.list")
	if err != nil {
		log.Errorf("cannot open cities list: %s", err)
		return
	}
	defer fd.Close()

	s := bufio.NewScanner(fd)
	for s.Scan() {
		AllCities = append(AllCities, s.Text())
	}
}
