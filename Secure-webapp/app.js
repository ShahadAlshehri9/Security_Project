const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');


// WEAK PASSWORD STORAGE
// We import bcrypt to replace the insecure MD5 hashing used before.
// bcrypt is a slow, salted hashing algorithm designed for passwords.
// MD5 is a fast hashing algorithm that is NOT suitable for passwords because it can be brute-forced very quickly using rainbow tables.
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12; // Higher = slower hash = harder to brute-force

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// SECURE SESSION CONFIGURATION — Encryption
// Session secret is stored in environment variables instead of hardcoding to protect sensitive data.
// It signs cookies to prevent tampering.
// secure: true ensures cookies are sent only over HTTPS.
// httpOnly: true prevents JavaScript access, reducing XSS risks.
require('dotenv').config();
app.use(session({
    //use environment variables (.env) to store sensitive data
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    //enable secure cookie settings
    cookie: {
        secure: true,
        httpOnly: true
    }
}));

const db = new sqlite3.Database(path.join(__dirname, 'app.db'));


// ------------------- ROUTES -------------------

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});


// SECURE REGISTRATION — SQL Injection 
// We use parameterized queries (?) to prevent SQL Injection by treating user input as data, not executable SQL
app.post('/register', async (req, res) => {
    const { username, password, fullName, email, age } = req.body;

    const hashedPwd = await bcrypt.hash(password, SALT_ROUNDS);
    const role = 'user';

    // parametrized query
    const query = `
        INSERT INTO users (username, password, fullName, email, age, role)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.run(query, [username, hashedPwd, fullName, email, age, role], function(err) {
        if (err) {
            return res.render('register', { error: 'Username already exists or invalid data.' });
        }
        res.redirect('/login');
    });
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // SECURE log in — SQL Injection 
    // We use parameterized queries (?) to prevent SQL Injection by treating user input as data, not executable SQL
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, user) => {
        if (err || !user) {
            return res.render('login', { error: 'Invalid credentials' });
        }
        
        // BCRYPT PASSWORD COMPARISON
        // Previously: we hashed the input with MD5 and compared directly in SQL.
        // Now: we fetch the user by username first, then use bcrypt.compare() to safely check the password against the stored bcrypt hash.
        // bcrypt.compare() checks the plain password against the stored hash
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.render('login', { error: 'Invalid credentials' });
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        req.session.fullName = user.fullName;
        req.session.email = user.email;
        req.session.age = user.age;
        req.session.created_at = user.created_at;
        res.redirect('/dashboard');
    });
});

// Middleware: checks login only
function requireLogin(req, res, next) {
    if (req.session.userId) return next();
    res.redirect('/login');
}


// ACCESS CONTROL (RBAC)
// A new middleware that checks BOTH that the user is logged in AND that their role is 'admin'. If not, they get a 403 Forbidden error
// instead of being shown the admin page.
// Previously: requireLogin() was used on /admin, which only checked if the user was logged in — any regular user could access /admin.

function requireAdmin(req, res, next) {
    if (!req.session.userId) {
        // Not logged in at all : redirect to login
        return res.redirect('/login');
    }
    if (req.session.role !== 'admin') {
        // Logged in but not an admin : block access
        return res.status(403).render('forbidden');
    }
    next();
}

// Dashboard (shows user details + comments)
app.get('/dashboard', requireLogin, (req, res) => {
    db.all(`SELECT * FROM comments ORDER BY created_at DESC`, (err, comments) => {
        if (err) comments = [];
        res.render('dashboard', {
            username: req.session.username,
            fullName: req.session.fullName,
            email: req.session.email,
            age: req.session.age,
            created_at: req.session.created_at,
            role: req.session.role,
            comments: comments
        });
    });
});

// XSS PREVENTION (server-side sanitization)
// Previously: user comment was inserted directly into the DB with no sanitization, and rendered raw in the view using <%- comment %>.
// Now: we strip all HTML tags from the comment before saving it,so even if a user submits <script>alert('XSS')</script>, it gets saved as plain text and cannot execute in the browser.
// The view also uses <%= %> (escaped output) as a second layer of defense.

function sanitizeInput(str) {
    // Remove all HTML tags using a regex to prevent script injection
    return str.replace(/<[^>]*>/g, '');
}

app.post('/comment', requireLogin, (req, res) => {
    const rawComment = req.body.comment;
    const userId = req.session.userId;
    const username = req.session.username;

    // Sanitize: strip HTML tags before storing
    const safeComment = sanitizeInput(rawComment);

    // Using parameterized query here to also prevent SQL injection on comments
    db.run(
        `INSERT INTO comments (user_id, username, comment) VALUES (?, ?, ?)`,
        [userId, username, safeComment],
        (err) => {
            if (err) console.error(err);
            res.redirect('/dashboard');
        }
    );
});


// ADMIN ROUTE NOW USES requireAdmin MIDDLEWARE
// Previously: app.get('/admin', requireLogin, ...) — any user could access.
// Now: app.get('/admin', requireAdmin, ...) — only role='admin' can access.

app.get('/admin', requireAdmin, (req, res) => {
    db.all(`SELECT id, username, fullName, email, role FROM users`, (err, users) => {
        if (err) users = [];
        res.render('admin', { users, currentUser: req.session.username });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// HTTPS SETUP — Secure Communication (TLS/SSL)
// We use HTTPS instead of HTTP to encrypt data transmitted between the client and server
// The SSL certificate (cert.pem) and private key (key.pem) enable encrypted communication
// This protects sensitive data such as passwords and session cookies from interception
const https = require('https');
const fs = require('fs');

const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};

https.createServer(options, app).listen(port, () => {
    console.log(`App running at https://localhost:${port}`);
});

