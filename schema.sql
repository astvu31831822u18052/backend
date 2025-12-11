-- Users table
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT CHECK(role IN ('student','faculty','admin')) NOT NULL DEFAULT 'student',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Facilities table
CREATE TABLE IF NOT EXISTS facilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT CHECK(type IN ('room','lab','sports')) NOT NULL,
  capacity INTEGER NOT NULL,
  location TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1
);

-- Bookings table
CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  facility_id INTEGER NOT NULL,
  start_time DATETIME NOT NULL,
  end_time DATETIME NOT NULL,
  status TEXT CHECK(status IN ('booked','cancelled')) NOT NULL DEFAULT 'booked',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (facility_id) REFERENCES facilities(id)
);

-- Seed facilities
INSERT INTO facilities (name, type, capacity, location) VALUES
('Room A101', 'room', 30, 'Academic Block A'),
('Computer Lab L2', 'lab', 40, 'Tech Block 2nd Floor'),
('Basketball Court', 'sports', 20, 'Sports Complex'),
('Room B204', 'room', 25, 'Academic Block B');

-- Optional: seed a demo admin (password: Admin@123)
-- Hash is for 'Admin@123' using bcrypt salt=10; change if needed.
INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES
('Admin', 'admin@campus.edu', '$2a$10$XgVd4S6lGkI0nB1b8EoV5O9m8Yc3Fzv2WvCjYJkFzqGmGk1zqkzAS', 'admin');
