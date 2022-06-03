package security

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// reporters keeps the ip that reported events and reported events in memory.
// [IP]eventsID. The events are concatenated using a comma between them
var reporters map[string]string

// this function checks if the ip already reported a given event. If not, it adds
// it to the in-mem map. This allows us to avoid duplicates reports.
func ReportEvent(ip, eid string) error {
	// check if the event has already been reported by the user
	events := reporters[ip]
	if strings.Contains(events, eid) {
		return fmt.Errorf("Tu as déjà signalé cet évènement.")
	}

	reporters[ip] = events + "," + eid
	logrus.Infof("updating reporters map: %v", reporters)
	return nil
}

func init() {
	reporters = make(map[string]string)
}
