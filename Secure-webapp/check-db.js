const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'app.db'));

db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
        console.log("Error:", err);
    } else {
        console.log(rows);
    }
});