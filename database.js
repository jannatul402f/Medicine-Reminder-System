const { DatabaseSync } = require("node:sqlite");

const db = new DatabaseSync("medicine.db");

// Create tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS medicines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        type TEXT,
        description TEXT,
        instructions TEXT
    );

    CREATE TABLE IF NOT EXISTS dosage_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        medicine_name TEXT NOT NULL,
        dose TEXT,
        time TEXT,
        meal_instruction TEXT
    );

    CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        medicine_name TEXT NOT NULL,
        date TEXT,
        time TEXT,
        frequency TEXT
    );
`);

console.log("SQLite database connected successfully.");

module.exports = db;