CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  ref TEXT UNIQUE,
  package_key TEXT NOT NULL,
  udid TEXT,
  delivery_email TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  payment_token TEXT,
  payment_id TEXT,
  paid_at TEXT,
  delivered_at TEXT,
  expires_at TEXT,
  delivery_note TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
