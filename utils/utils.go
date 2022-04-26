package utils

import "strings"

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
