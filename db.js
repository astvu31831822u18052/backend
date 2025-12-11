const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const dbFile = path.join(__dirname, 'campus.db');
const schemaFile = path.join(__dirname, 'schema.sql');

const db = new sqlite3.Database(dbFile);

function init() {
  const schema = fs.readFileSync(schemaFile, 'utf8');
  db.exec(schema, (err) => {
    if (err) console.error('Schema init error:', err);
    else console.log('SQLite schema initialized.');
  });
}

module.exports = { db, init };
