const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

// Wrap db operations in Promises for clean async/await syntax
const dbQuery = {
  run(sql, params = []) {
    return new Promise((resolve, reject) => {
      db.run(sql, params, function (err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  },
  
  get(sql, params = []) {
    return new Promise((resolve, reject) => {
      db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  },
  
  all(sql, params = []) {
    return new Promise((resolve, reject) => {
      db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }
};

// Initialize DB schema
async function initDatabase() {
  console.log('Initializing SQLite database schema...');
  
  // Enable foreign keys
  await dbQuery.run('PRAGMA foreign_keys = ON;');
  
  // Users Table
  await dbQuery.run(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      phone_number TEXT,
      role TEXT DEFAULT 'user',
      two_fa_enabled INTEGER DEFAULT 0,
      two_fa_method TEXT,
      totp_secret TEXT,
      backup_codes TEXT, -- JSON string of hashed backup codes
      lockout_until INTEGER DEFAULT 0, -- Lockout timestamp in ms
      failed_login_attempts INTEGER DEFAULT 0, -- Counter for rate limiting password attempts
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);
  
  // Indexes for faster lookups
  await dbQuery.run('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);');
  await dbQuery.run('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);');

  // 2FA Codes Table
  await dbQuery.run(`
    CREATE TABLE IF NOT EXISTS two_fa_codes (
      code_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code_hash TEXT NOT NULL, -- SHA-256 hash of the SMS/Email code
      expiration_time INTEGER NOT NULL, -- Timestamp in ms
      is_used INTEGER DEFAULT 0, -- 0 = false, 1 = true
      attempt_count INTEGER DEFAULT 0, -- Counter for rate limiting code verification attempts
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
  `);

  // Sessions Table
  await dbQuery.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT UNIQUE NOT NULL, -- SHA-256 hash of the session token
      ip_address TEXT,
      device_info TEXT,
      expires_at INTEGER NOT NULL, -- Timestamp in ms
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    );
  `);
  
  // Add role column to existing users table if it doesn't exist
  try {
    await dbQuery.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';");
    console.log('Added role column to users table.');
  } catch (e) {
    // Ignore error if column already exists
  }
  
  console.log('Database schema successfully initialized.');
}

module.exports = {
  db,
  dbQuery,
  initDatabase,
  uuidv4
};
