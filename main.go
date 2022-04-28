package main

import (
	"log"
	"os"

	"github.com/namsral/flag"

	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/database"
	"github.com/manifeste-info/webapp/handlers"
	"github.com/manifeste-info/webapp/mail"
)

func main() {
	var host, port, user, pass, name string
	var mgAPIKey string
	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "MANIFESTE", 0)
	fs.StringVar(&host, "db-host", "postgres", "Database host")
	fs.StringVar(&port, "db-port", "5432", "Database port")
	fs.StringVar(&user, "db-user", os.Getenv("POSTGRES_USER"), "Database user")
	fs.StringVar(&pass, "db-pass", os.Getenv("POSTGRES_PASSWORD"), "Database pass")
	fs.StringVar(&name, "db-name", os.Getenv("POSTGRES_DB"), "Database name")
	fs.StringVar(&mgAPIKey, "mg-api-key", os.Getenv("MAILGUN_API_KEY"), "Mailgun API key")
	fs.BoolVar(&config.UnderDevelopment, "dev", false, "Display under development banner")

	if err := database.NewConnection(host, port, user, pass, name); err != nil {
		log.Fatal(err)
	}

	mail.CreateInstance(mgAPIKey)
	r, err := handlers.CreateRouter()
	if err != nil {
		log.Fatalf("fatal: cannot create router: %s\n", err)
	}
	if err := r.Run(); err != nil {
		log.Fatalf("error: cannot run server: %s\n", err)
	}
}
