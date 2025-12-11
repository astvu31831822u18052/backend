require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, init } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

init();

app.use(cors());
app.use(express.json());

// Helpers
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing token' });
  }
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function validateTimes(start_time, end_time) {
  const start = new Date(start_time);
  const end = new Date(end_time);
  return start instanceof Date && !isNaN(start) &&
         end instanceof Date && !isNaN(end) &&
         end > start;
}

// Auth routes
app.post('/api/auth/signup', (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Missing fields' });
  }
  const hashed = bcrypt.hashSync(password, 10);
  const roleVal = role && ['student','faculty','admin'].includes(role) ? role : 'student';

  const stmt = db.prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)');
  stmt.run(name, email.toLowerCase(), hashed, roleVal, function(err) {
    if (err) {
      if (String(err.message).includes('UNIQUE')) {
        return res.status(409).json({ message: 'Email already exists' });
      }
      return res.status(500).json({ message: 'Signup error' });
    }
    const token = jwt.sign({ id: this.lastID, email, role: roleVal, name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Missing fields' });

  db.get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()], (err, user) => {
    if (err) return res.status(500).json({ message: 'Login error' });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  });
});

// Facilities
app.get('/api/facilities', (req, res) => {
  db.all('SELECT * FROM facilities WHERE is_active = 1', [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Fetch facilities error' });
    res.json(rows);
  });
});

// Create booking
app.post('/api/bookings', authMiddleware, (req, res) => {
  const { facility_id, start_time, end_time } = req.body;
  if (!facility_id || !start_time || !end_time) return res.status(400).json({ message: 'Missing fields' });
  if (!validateTimes(start_time, end_time)) return res.status(400).json({ message: 'Invalid time range' });

  // Check overlap
  const overlapQuery = `
    SELECT COUNT(*) as cnt FROM bookings
    WHERE facility_id = ?
      AND status = 'booked'
      AND NOT (end_time <= ? OR start_time >= ?)
  `;
  db.get(overlapQuery, [facility_id, start_time, end_time], (err, row) => {
    if (err) return res.status(500).json({ message: 'Overlap check error' });
    if (row.cnt > 0) return res.status(409).json({ message: 'Time slot not available' });

    const stmt = db.prepare('INSERT INTO bookings (user_id, facility_id, start_time, end_time, status) VALUES (?, ?, ?, ?, "booked")');
    stmt.run(req.user.id, facility_id, start_time, end_time, function(err2) {
      if (err2) return res.status(500).json({ message: 'Create booking error' });
      db.get('SELECT * FROM bookings WHERE id = ?', [this.lastID], (err3, booking) => {
        if (err3) return res.status(500).json({ message: 'Fetch booking error' });
        res.status(201).json(booking);
      });
    });
  });
});

// Update booking time (owner or admin)
app.put('/api/bookings/:id', authMiddleware, (req, res) => {
  const id = req.params.id;
  const { start_time, end_time } = req.body;
  if (!validateTimes(start_time, end_time)) return res.status(400).json({ message: 'Invalid time range' });

  db.get('SELECT * FROM bookings WHERE id = ?', [id], (err, booking) => {
    if (err) return res.status(500).json({ message: 'Fetch booking error' });
    if (!booking) return res.status(404).json({ message: 'Booking not found' });
    if (booking.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized' });
    }

    const overlapQuery = `
      SELECT COUNT(*) as cnt FROM bookings
      WHERE facility_id = ?
        AND id <> ?
        AND status = 'booked'
        AND NOT (end_time <= ? OR start_time >= ?)
    `;
    db.get(overlapQuery, [booking.facility_id, id, start_time, end_time], (err2, row) => {
      if (err2) return res.status(500).json({ message: 'Overlap check error' });
      if (row.cnt > 0) return res.status(409).json({ message: 'Time slot not available' });

      db.run('UPDATE bookings SET start_time = ?, end_time = ? WHERE id = ?', [start_time, end_time, id], (err3) => {
        if (err3) return res.status(500).json({ message: 'Update booking error' });
        db.get('SELECT * FROM bookings WHERE id = ?', [id], (err4, updated) => {
          if (err4) return res.status(500).json({ message: 'Fetch updated booking error' });
          res.json(updated);
        });
      });
    });
  });
});

// Cancel booking
app.delete('/api/bookings/:id', authMiddleware, (req, res) => {
  const id = req.params.id;
  db.get('SELECT * FROM bookings WHERE id = ?', [id], (err, booking) => {
    if (err) return res.status(500).json({ message: 'Fetch booking error' });
    if (!booking) return res.status(404).json({ message: 'Booking not found' });
    if (booking.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized' });
    }
    db.run('UPDATE bookings SET status = "cancelled" WHERE id = ?', [id], (err2) => {
      if (err2) return res.status(500).json({ message: 'Cancel booking error' });
      res.json({ message: 'Booking cancelled' });
    });
  });
});

// My bookings
app.get('/api/bookings/me', authMiddleware, (req, res) => {
  db.all(
    `SELECT b.*, f.name as facility_name, f.location, f.type
     FROM bookings b
     JOIN facilities f ON f.id = b.facility_id
     WHERE b.user_id = ?
     ORDER BY b.start_time DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Fetch my bookings error' });
      res.json(rows);
    }
  );
});

// Usage trends (bookings count per facility per day)
app.get('/api/trends', authMiddleware, (req, res) => {
  const query = `
    SELECT
      f.name as facility_name,
      DATE(b.start_time) as day,
      COUNT(*) as bookings_count
    FROM bookings b
    JOIN facilities f ON f.id = b.facility_id
    WHERE b.status = 'booked'
    GROUP BY f.name, DATE(b.start_time)
    ORDER BY day DESC, facility_name ASC
    LIMIT 200
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Fetch trends error' });
    res.json(rows);
  });
});

app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));

