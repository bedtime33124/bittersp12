const crypto = require("crypto");
const fs = require("fs");

const [email, password] = process.argv.slice(2);
if (!email || !password || password.length < 12) {
  console.error('Usage: node create-admin.js your@email.com "password-12-chars-or-more"');
  process.exit(1);
}

const ITERATIONS = 100000;
const salt = crypto.randomBytes(16);
const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, "sha256");
const stored = `pbkdf2$${ITERATIONS}$${salt.toString("hex")}$${hash.toString("hex")}`;
const safeEmail = email.trim().toLowerCase().replace(/'/g, "''");

fs.writeFileSync("admin.sql",
  `INSERT INTO users (email, password_hash, is_admin) VALUES ('${safeEmail}', '${stored}', 1) ` +
  `ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash, is_admin = 1;\n`
);

console.log("Wrote admin.sql. Next: npx wrangler d1 execute bittersp12 --remote --file admin.sql");
