package main

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"

	"github.com/manifeste-info/webapp/app"
	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/database"
	"github.com/manifeste-info/webapp/mail"
	"github.com/manifeste-info/webapp/utils"

	flags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

var (
	Version   string
	BuildDate string
)

type options struct {
	PostgresHost string `short:"h" long:"postgres-host" description:"PostgreSQL host"`
	PostgresPort string `short:"p" long:"postgres-port" description:"PostgreSQL port"`
	PostgresUser string `short:"u" long:"postgres-user" description:"PostgreSQL user"`
	PostgresPass string `short:"P" long:"postgres-pass" description:"PostgreSQL pass"`
}

func main() {
	var opts options
	args, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		log.Fatalf("cannot parse options: %s", err)
	}

	// before doing any action, we want to do the "CLI" behavior
	if len(args) == 2 {
		switch args[1] {
		case "ulid":
			fmt.Println(utils.CreateULID())
			os.Exit(0)
		case "version":
			fmt.Printf("%s (built: %s)\n", Version, BuildDate)
			os.Exit(0)
		}
	}

	if err := opts.Configure(); err != nil {
		log.Errorf("cannot configure and validate options: %s", err)
	}

	var mask string
	for range opts.PostgresPass {
		mask = mask + "*"
	}
	c := config.New()
	fmt.Printf(`Database host: %s
Database port: %s
Database user: %s
Database pass: %s
--
Environment: %s
Notifier: %s
`, opts.PostgresHost, opts.PostgresPort, opts.PostgresUser, mask, c.Env, c.Notifier)

	a, err := app.New(c)
	if err != nil {
		log.Fatalf("cannot create app: %s", err)
	}

	if err := database.NewConnection(opts.PostgresHost, opts.PostgresPort, opts.PostgresUser, opts.PostgresPass, "manifeste"); err != nil {
		log.Fatal(err)
	}

	// if asked in CLI, migrate the database
	if len(args) == 2 {
		switch args[1] {
		case "migrate:up":
			time.Sleep(1 * time.Second)
			driver, err := postgres.WithInstance(database.DB, &postgres.Config{})
			if err != nil {
				log.Fatalf("cannot create migration driver instance: %s", err)
			}
			m, err := migrate.NewWithDatabaseInstance("file:///build/migrations", "postgres", driver)
			if err != nil {
				log.Fatalf("cannot create migrator: %s", err)
			}
			err = m.Up()
			if err != nil {
				if err == migrate.ErrNoChange {
					log.Warn("cannot migrate up: no changes")
				} else {
					log.Fatalf("cannot migrate up database: %s", err)
				}
			}
			log.Info("successfully migrated up the database")
		case "migrate:down":
			time.Sleep(1 * time.Second)
			driver, err := postgres.WithInstance(database.DB, &postgres.Config{})
			if err != nil {
				log.Fatalf("cannot create migration driver instance: %s", err)
			}
			m, err := migrate.NewWithDatabaseInstance("file:///build/migrations", "postgres", driver)
			if err != nil {
				log.Fatalf("cannot create migrator: %s", err)
			}
			if err := m.Down(); err != nil {
				log.Fatalf("cannot migrate down database: %s", err)
			}
			log.Info("successfully migrated down the database")
		}
	}
	if err := mail.CreateInstance(); err != nil {
		log.Fatalf("fatal: cannot create mail instance: %s", err)
	}
	r, err := app.CreateRouter(a)
	if err != nil {
		log.Fatalf("fatal: cannot create router: %s", err)
	}
	if err := r.Run(); err != nil {
		log.Fatalf("error: cannot run server: %s", err)
	}
}

// Configure checks if the options are correctly configured, and adjust them if
// needed
func (o *options) Configure() error {
	// try to load any .env file
	if err := godotenv.Load(); err != nil {
		return err
	}

	if o.PostgresHost == "" {
		o.PostgresHost = os.Getenv("POSTGRES_HOST")
	}

	if o.PostgresPort == "" {
		o.PostgresPort = os.Getenv("POSTGRES_PORT")
		if o.PostgresPort == "" {
			o.PostgresPort = "5432"
		}
	}

	if o.PostgresUser == "" {
		o.PostgresUser = os.Getenv("POSTGRES_USER")
	}

	if o.PostgresPass == "" {
		o.PostgresPass = os.Getenv("POSTGRES_PASSWORD")
	}

	return nil
}
