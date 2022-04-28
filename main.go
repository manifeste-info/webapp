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
	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "MANIFESTE", 0)
	fs.StringVar(&host, "db-host", "postgres", "Database host")
	fs.StringVar(&port, "db-port", "5432", "Database port")
	fs.StringVar(&user, "db-user", os.Getenv("POSTGRES_USER"), "Database user")
	fs.StringVar(&pass, "db-pass", os.Getenv("POSTGRES_PASSWORD"), "Database pass")
	fs.StringVar(&name, "db-name", os.Getenv("POSTGRES_DB"), "Database name")
	fs.BoolVar(&config.UnderDevelopment, "dev", false, "Display under development banner")

	if err := database.NewConnection(host, port, user, pass, name); err != nil {
		log.Fatal(err)
	}

	if err := mail.CreateInstance(); err != nil {
		log.Fatalf("fatal: cannot create mail instance: %s\n", err)
	}
	r, err := handlers.CreateRouter()
	if err != nil {
		log.Fatalf("fatal: cannot create router: %s\n", err)
	}
	if err := r.Run(); err != nil {
		log.Fatalf("error: cannot run server: %s\n", err)
	}
}
