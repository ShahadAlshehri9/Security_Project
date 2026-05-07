// initDb.js
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const dbPath = path.join(__dirname, 'app.db');
const db = new sqlite3.Database(dbPath);

// INSECURE hash (MD5) – required for "Weak Password Storage" vulnerability
function md5Hash(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

db.serialize(() => {
    // Users table includes 'role' for RBAC (Access Control vulnerability)
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            fullName TEXT,
            email TEXT,
            age INTEGER,
            role TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Comments table – stores unsanitized user input (Stored XSS vulnerability)
    db.run(`
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Insert admin with MD5-hashed password (insecure storage)
    const adminPassword = md5Hash('admin123');
    db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, row) => {
        if (!row) {
            db.run(`
                INSERT INTO users (username, password, fullName, email, age, role)
                VALUES (?, ?, ?, ?, ?, ?)
            `, ['admin', adminPassword, 'Admin User', 'admin@example.com', 30, 'admin']);
            console.log('Admin user created (MD5 hash)');
        }
    });

    // Sample XSS comment – demonstrates stored XSS vulnerability
    db.get(`SELECT * FROM comments WHERE comment LIKE '%<script>%'`, (err, row) => {
        if (!row) {
            db.run(`INSERT INTO comments (user_id, username, comment) VALUES (?, ?, ?)`,
                [1, 'admin', '<script>alert("XSS")</script>']);
            console.log('Sample XSS comment added');
        }
    });
});

// Close DB after all operations (reliable version)
db.close(() => {
    console.log('Database initialized with vulnerable schema (MD5, XSS comment, RBAC column).');
});
