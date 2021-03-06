CREATE TABLE IF NOT EXISTS users(
  id CHAR(26) PRIMARY KEY,
  email TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin BOOLEAN NOT NULL,
  has_confirmed_account BOOLEAN NOT NULL,
  account_validation_token TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);