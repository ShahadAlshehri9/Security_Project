const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const dbPath = path.join(__dirname, 'app.db');
const db = new sqlite3.Database(dbPath);

function md5Hash(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

db.serialize(() => {

    db.run(`CREATE TABLE IF NOT EXISTS users (...)`);
    db.run(`CREATE TABLE IF NOT EXISTS comments (...)`);

    const adminPassword = md5Hash('admin123');

    db.get(`SELECT * FROM users WHERE username = 'admin'`, (err, row) => {
        if (!row) {
            db.run(`
                INSERT INTO users (username, password, fullName, email, age, role)
                VALUES (?, ?, ?, ?, ?, ?)
            `, ['admin', adminPassword, 'Admin User', 'admin@example.com', 30, 'admin']);

            console.log('Admin user created: admin / admin123');
        }
    });

    db.get(`SELECT * FROM comments WHERE comment LIKE '%<script>%'`, (err, row) => {
        if (!row) {
            db.run(`INSERT INTO comments (user_id, username, comment) VALUES (?, ?, ?)`,
                [1, 'admin', '<script>alert("XSS")</script>']);

            console.log('Sample XSS comment added');
        }
    });


    db.close(() => {
        console.log('Database initialized with extended schema.');
    });

});