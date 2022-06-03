CREATE TABLE IF NOT EXISTS events(
  id CHAR(26) PRIMARY KEY,
  city VARCHAR(100) NOT NULL,
  date TIMESTAMP NOT NULL,
  address TEXT NOT NULL,
  description TEXT NOT NULL,
  organizer TEXT NOT NULL,
  link TEXT,
  created_by CHAR(26),
  category TEXT NOT NULL,
  num_of_reports INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);