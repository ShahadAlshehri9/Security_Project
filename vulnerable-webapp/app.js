const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));  // for styles.css, images
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Insecure session (no secure flag, HTTP only)
app.use(session({
    secret: 'insecure_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

const db = new sqlite3.Database(path.join(__dirname, 'app.db'));

function md5Hash(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// ------------------- ROUTES -------------------

app.get('/', (req, res) => {
    res.render('index');  // new index page (hero)
});

// Registration page
app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

// VULNERABLE REGISTRATION (SQL injection)
app.post('/register', (req, res) => {
    const { username, password, fullName, email, age } = req.body;
    const hashedPwd = md5Hash(password);
    const role = 'user';
    // Direct string concatenation → SQL injection
    const query = `
        INSERT INTO users (username, password, fullName, email, age, role)
        VALUES ('${username}', '${hashedPwd}', '${fullName}', '${email}', ${age}, '${role}')
    `;
    db.run(query, function(err) {
        if (err) {
            return res.render('register', { error: 'Username already exists or invalid data.' });
        }
        res.redirect('/login');
    });
});

// Login page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// VULNERABLE LOGIN (SQL injection)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const hashedPwd = md5Hash(password);
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashedPwd}'`;
    db.get(query, (err, user) => {
        if (err || !user) {
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

// Middleware: only checks login, NOT role
function requireLogin(req, res, next) {
    if (req.session.userId) return next();
    res.redirect('/login');
}

// Dashboard (shows user details + XSS comments)
app.get('/dashboard', requireLogin, (req, res) => {
    // Get all comments (no sanitization → XSS)
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

// Add comment (XSS injection point)
app.post('/comment', requireLogin, (req, res) => {
    const { comment } = req.body;
    const userId = req.session.userId;
    const username = req.session.username;
    // Vulnerable: direct insertion, no sanitization
    db.run(`INSERT INTO comments (user_id, username, comment) VALUES (${userId}, '${username}', '${comment}')`,
        (err) => {
            if (err) console.error(err);
            res.redirect('/dashboard');
        });
});

// ADMIN PAGE - Broken Access Control (any logged-in user can access)
app.get('/admin', requireLogin, (req, res) => {
    db.all(`SELECT id, username, fullName, email, role FROM users`, (err, users) => {
        if (err) users = [];
        res.render('admin', { users, currentUser: req.session.username });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.listen(port, () => {
    console.log(`Vulnerable app running at http://localhost:${port}`);
});
