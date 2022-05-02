package main

import (
	"os"

	"github.com/manifeste-info/webapp/app"
	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/database"
	"github.com/manifeste-info/webapp/handlers"
	"github.com/manifeste-info/webapp/mail"
	"github.com/namsral/flag"
	log "github.com/sirupsen/logrus"
)

func main() {
	var host, port, user, pass, name string
	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "MANIFESTE", 0)
	fs.StringVar(&host, "db-host", "postgres", "Database host")
	fs.StringVar(&port, "db-port", "5432", "Database port")
	fs.StringVar(&user, "db-user", os.Getenv("POSTGRES_USER"), "Database user")
	fs.StringVar(&pass, "db-pass", os.Getenv("POSTGRES_PASSWORD"), "Database pass")
	fs.StringVar(&name, "db-name", os.Getenv("POSTGRES_DB"), "Database name")

	c, err := config.New()
	if err != nil {
		log.Fatalf("cannot create config: %s", err)
	}

	log.Infof("environment: %s", c.Env)
	log.Infof("notifier: %s", c.Notifier)
	a, err := app.New(c)
	if err != nil {
		log.Fatalf("cannot create app: %s", err)
	}

	if err := database.NewConnection(host, port, user, pass, name); err != nil {
		log.Fatal(err)
	}

	if err := mail.CreateInstance(); err != nil {
		log.Fatalf("fatal: cannot create mail instance: %s\n", err)
	}
	r, err := handlers.CreateRouter(a)
	if err != nil {
		log.Fatalf("fatal: cannot create router: %s\n", err)
	}
	if err := r.Run(); err != nil {
		log.Fatalf("error: cannot run server: %s\n", err)
	}
}
