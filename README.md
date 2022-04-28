# _Manifeste !_ 

## Development

### Start the development stack

Create a `.env` file following the format:

```
POSTGRES_USER=user
POSTGRES_PASSWORD=password
POSTGRES_DB=manifeste

SES_SMTP_USER=xxx
SES_SMTP_PASS=xxxxxxx
SES_SMTP_HOST=email-smtp.xxxx.amazonaws.com
SES_SMTP_PORT=587
```

Then you can start the stack:

```
docker-compose build && docker-compose up
```

### Migrate the databases

Once the PostgreSQL container is running, you can migrate the database:

```
export POSTGRESQL_URL="postgres://user:password@localhost:5432/manifeste?sslmode=disable"
migrate -database ${POSTGRESQL_URL} -path db/migrations up
```

([migrate](https://github.com/golang-migrate/migrate) tool is required).

Then you're ready to go!

## License

[MIT](https://choosealicense.com/licenses/mit/)