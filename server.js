const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Database } = require("node:sqlite");

const app = express();
const PORT = 3000;

// ================= DATABASE =================

const db = new Database(
    path.join(__dirname, "medicine.db")
);

console.log("SQLite database connected successfully.");


// ================= MIDDLEWARE =================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);


// ================= DATABASE TABLES =================

// Users
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`);


// Medicines
db.exec(`
    CREATE TABLE IF NOT EXISTS medicines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT,
        description TEXT,
        instructions TEXT
    )
`);


// Dosage schedules
db.exec(`
    CREATE TABLE IF NOT EXISTS dosage_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        medicine_name TEXT NOT NULL,
        dose TEXT NOT NULL,
        time TEXT NOT NULL,
        meal_instruction TEXT
    )
`);


// Reminders
db.exec(`
    CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        medicine_name TEXT NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        frequency TEXT
    )
`);


// Missed doses
db.exec(`
    CREATE TABLE IF NOT EXISTS missed_doses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        medicine_name TEXT NOT NULL,
        date TEXT NOT NULL,
        status TEXT
    )
`);


// Medicine stock
db.exec(`
    CREATE TABLE IF NOT EXISTS medicine_stock (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        medicine_name TEXT NOT NULL,
        total_quantity INTEGER NOT NULL,
        used_quantity INTEGER NOT NULL,
        expiry_date TEXT
    )
`);


// Refill reminders
db.exec(`
    CREATE TABLE IF NOT EXISTS refill_reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        medicine_name TEXT NOT NULL,
        remaining_quantity INTEGER NOT NULL,
        refill_date TEXT NOT NULL,
        notes TEXT
    )
`);


// Medication history
db.exec(`
    CREATE TABLE IF NOT EXISTS medication_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        medicine_name TEXT NOT NULL,
        dose TEXT NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        status TEXT NOT NULL,
        notes TEXT
    )
`);


// Prescriptions
db.exec(`
    CREATE TABLE IF NOT EXISTS prescriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        doctor_name TEXT,
        date TEXT,
        notes TEXT,
        file_data TEXT
    )
`);


// Symptoms
db.exec(`
    CREATE TABLE IF NOT EXISTS symptoms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symptom TEXT NOT NULL,
        date TEXT NOT NULL,
        severity TEXT,
        duration TEXT,
        notes TEXT
    )
`);


// Notifications
db.exec(`
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        medicine TEXT,
        message TEXT,
        date TEXT,
        time TEXT,
        sent INTEGER DEFAULT 0
    )
`);


// ================= HOME =================

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "login.html"
        )
    );

});


// ================= DATABASE TEST =================

app.get("/api/database-test", (req, res) => {

    try {

        const result = db.prepare(`
            SELECT 1 AS test
        `).get();

        res.json({
            success: true,
            message: "Database connected successfully.",
            result: result
        });

    } catch (error) {

        console.error(
            "Database test error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Database test failed."
        });

    }

});


// ================= PASSWORD HELPERS =================

function hashPassword(password) {

    const salt =
        crypto.randomBytes(16).toString("hex");

    const hash =
        crypto.scryptSync(
            password,
            salt,
            64
        ).toString("hex");

    return `${salt}:${hash}`;

}


function verifyPassword(
    password,
    storedPassword
) {

    try {

        const parts =
            storedPassword.split(":");

        if (parts.length !== 2) {
            return false;
        }

        const salt = parts[0];
        const storedHash = parts[1];

        const hash =
            crypto.scryptSync(
                password,
                salt,
                64
            ).toString("hex");

        return crypto.timingSafeEqual(
            Buffer.from(hash, "hex"),
            Buffer.from(storedHash, "hex")
        );

    } catch (error) {

        return false;

    }

}


// ================= REGISTER =================

app.post("/api/register", (req, res) => {

    try {

        const {
            name,
            email,
            password
        } = req.body;


        if (
            !name ||
            !email ||
            !password
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Please fill all fields."
            });

        }


        if (password.length < 8) {

            return res.status(400).json({
                success: false,
                message:
                    "Password must be at least 8 characters."
            });

        }


        const existingUser =
            db.prepare(`
                SELECT id
                FROM users
                WHERE email = ?
            `).get(email);


        if (existingUser) {

            return res.status(400).json({
                success: false,
                message:
                    "Email already registered."
            });

        }


        const hashedPassword =
            hashPassword(password);


        const result =
            db.prepare(`
                INSERT INTO users
                (name, email, password)
                VALUES (?, ?, ?)
            `).run(
                name,
                email,
                hashedPassword
            );


        res.json({
            success: true,
            message:
                "Registration successful.",
            userId:
                result.lastInsertRowid
        });


    } catch (error) {

        console.error(
            "Registration error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Registration failed."
        });

    }

});


// ================= LOGIN =================

app.post("/api/login", (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;


        if (
            !email ||
            !password
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Please enter email and password."
            });

        }


        const user =
            db.prepare(`
                SELECT
                    id,
                    name,
                    email,
                    password
                FROM users
                WHERE email = ?
            `).get(email);


        if (!user) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid email or password."
            });

        }


        const valid =
            verifyPassword(
                password,
                user.password
            );


        if (!valid) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid email or password."
            });

        }


        res.json({
            success: true,
            message: "Login successful.",
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });


    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Login failed."
        });

    }

});


// ============================================================
// ================= MEDICINE PROFILE =========================
// ============================================================

// Add medicine
app.post("/api/medicines", (req, res) => {

    try {

        const {
            name,
            type,
            description,
            instructions
        } = req.body;


        if (!name) {

            return res.status(400).json({
                success: false,
                message:
                    "Medicine name is required."
            });

        }


        const result =
            db.prepare(`
                INSERT INTO medicines
                (name, type, description, instructions)
                VALUES (?, ?, ?, ?)
            `).run(
                name,
                type || "",
                description || "",
                instructions || ""
            );


        res.json({
            success: true,
            message:
                "Medicine saved successfully.",
            id:
                result.lastInsertRowid
        });


    } catch (error) {

        console.error(
            "Medicine save error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to save medicine."
        });

    }

});


// Get medicines
app.get("/api/medicines", (req, res) => {

    try {

        const medicines =
            db.prepare(`
                SELECT
                    id,
                    name,
                    type,
                    description,
                    instructions
                FROM medicines
                ORDER BY id DESC
            `).all();


        res.json({
            success: true,
            medicines: medicines
        });


    } catch (error) {

        console.error(
            "Medicine load error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to load medicines."
        });

    }

});


// Delete medicine
app.delete("/api/medicines/:id", (req, res) => {

    try {

        const id =
            Number(req.params.id);


        const result =
            db.prepare(`
                DELETE FROM medicines
                WHERE id = ?
            `).run(id);


        if (result.changes === 0) {

            return res.status(404).json({
                success: false,
                message:
                    "Medicine not found."
            });

        }


        res.json({
            success: true,
            message:
                "Medicine deleted successfully."
        });


    } catch (error) {

        console.error(
            "Medicine delete error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Unable to delete medicine."
        });

    }

});


// ============================================================
// ================= DOSAGE SCHEDULE ==========================
// ============================================================

// Add dosage
app.post(
    "/api/dosage-schedules",
    (req, res) => {

        try {

            const {
                medicine_name,
                dose,
                time,
                meal_instruction
            } = req.body;


            if (
                !medicine_name ||
                !dose ||
                !time
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please fill all required fields."
                });

            }


            const result =
                db.prepare(`
                    INSERT INTO dosage_schedules
                    (
                        medicine_name,
                        dose,
                        time,
                        meal_instruction
                    )
                    VALUES (?, ?, ?, ?)
                `).run(
                    medicine_name,
                    dose,
                    time,
                    meal_instruction || ""
                );


            res.json({
                success: true,
                message:
                    "Dosage schedule saved successfully.",
                id:
                    result.lastInsertRowid
            });


        } catch (error) {

            console.error(
                "Dosage save error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save dosage schedule."
            });

        }

    }
);


// Get dosage
app.get(
    "/api/dosage-schedules",
    (req, res) => {

        try {

            const dosages =
                db.prepare(`
                    SELECT
                        id,
                        medicine_name,
                        dose,
                        time,
                        meal_instruction
                    FROM dosage_schedules
                    ORDER BY id DESC
                `).all();


            res.json({
                success: true,
                dosages: dosages
            });


        } catch (error) {

            console.error(
                "Dosage load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load dosage schedules."
            });

        }

    }
);


// Delete dosage
app.delete(
    "/api/dosage-schedules/:id",
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            const result =
                db.prepare(`
                    DELETE FROM dosage_schedules
                    WHERE id = ?
                `).run(id);


            if (result.changes === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Dosage schedule not found."
                });

            }


            res.json({
                success: true,
                message:
                    "Dosage schedule deleted successfully."
            });


        } catch (error) {

            console.error(
                "Dosage delete error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete dosage schedule."
            });

        }

    }
);


// ============================================================
// ================= REMINDER =================================
// ============================================================

// Add reminder
app.post(
    "/api/reminders",
    (req, res) => {

        try {

            const {
                medicine_name,
                date,
                time,
                frequency
            } = req.body;


            if (
                !medicine_name ||
                !date ||
                !time
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please fill all required fields."
                });

            }


            const result =
                db.prepare(`
                    INSERT INTO reminders
                    (
                        medicine_name,
                        date,
                        time,
                        frequency
                    )
                    VALUES (?, ?, ?, ?)
                `).run(
                    medicine_name,
                    date,
                    time,
                    frequency || "Once"
                );


            res.json({
                success: true,
                message:
                    "Reminder saved successfully.",
                id:
                    result.lastInsertRowid
            });


        } catch (error) {

            console.error(
                "Reminder save error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save reminder."
            });

        }

    }
);


// Get reminders
app.get(
    "/api/reminders",
    (req, res) => {

        try {

            const reminders =
                db.prepare(`
                    SELECT
                        id,
                        medicine_name,
                        date,
                        time,
                        frequency
                    FROM reminders
                    ORDER BY id DESC
                `).all();


            res.json({
                success: true,
                reminders:
                    reminders
            });


        } catch (error) {

            console.error(
                "Reminder load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load reminders."
            });

        }

    }
);


// Delete reminder
app.delete(
    "/api/reminders/:id",
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            const result =
                db.prepare(`
                    DELETE FROM reminders
                    WHERE id = ?
                `).run(id);


            if (result.changes === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Reminder not found."
                });

            }


            res.json({
                success: true,
                message:
                    "Reminder deleted successfully."
            });


        } catch (error) {

            console.error(
                "Reminder delete error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete reminder."
            });

        }

    }
);


// ============================================================
// ================= MISSED DOSE ==============================
// ============================================================

// Add missed dose
app.post(
    "/api/missed-doses",
    (req, res) => {

        try {

            const {
                medicine_name,
                date,
                time,
                reason
            } = req.body;


            if (
                !medicine_name ||
                !date
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please fill all required fields."
                });

            }


            const finalDate =
                time
                    ? `${date} ${time}`
                    : date;


            const result =
                db.prepare(`
                    INSERT INTO missed_doses
                    (
                        medicine_name,
                        date,
                        status
                    )
                    VALUES (?, ?, ?)
                `).run(
                    medicine_name,
                    finalDate,
                    reason || "Missed"
                );


            res.json({
                success: true,
                message:
                    "Missed dose saved successfully.",
                id:
                    result.lastInsertRowid
            });


        } catch (error) {

            console.error(
                "Missed dose save error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save missed dose."
            });

        }

    }
);


// Get missed doses
app.get(
    "/api/missed-doses",
    (req, res) => {

        try {

            const rows =
                db.prepare(`
                    SELECT
                        id,
                        medicine_name,
                        date,
                        status
                    FROM missed_doses
                    ORDER BY id DESC
                `).all();


            const missedDoses =
                rows.map(row => ({

                    id:
                        row.id,

                    medicine_name:
                        row.medicine_name,

                    date:
                        row.date,

                    time:
                        "",

                    reason:
                        row.status

                }));


            res.json({
                success: true,
                missedDoses:
                    missedDoses
            });


        } catch (error) {

            console.error(
                "Missed dose load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load missed doses."
            });

        }

    }
);


// Delete missed dose
app.delete(
    "/api/missed-doses/:id",
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            const result =
                db.prepare(`
                    DELETE FROM missed_doses
                    WHERE id = ?
                `).run(id);


            if (result.changes === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Missed dose not found."
                });

            }


            res.json({
                success: true,
                message:
                    "Missed dose deleted successfully."
            });


        } catch (error) {

            console.error(
                "Missed dose delete error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete missed dose."
            });

        }

    }
);


// ============================================================
// ================= MEDICINE STOCK ============================
// ============================================================

// Add medicine stock
app.post(
    "/api/medicine-stock",
    (req, res) => {

        try {

            const {
                medicine_name,
                total_quantity,
                used_quantity,
                expiry_date
            } = req.body;


            if (
                !medicine_name ||
                total_quantity === undefined ||
                used_quantity === undefined
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please fill all required fields."
                });

            }


            const total =
                Number(total_quantity);

            const used =
                Number(used_quantity);


            if (
                isNaN(total) ||
                isNaN(used)
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Quantity must be a number."
                });

            }


            if (
                total < 0 ||
                used < 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Quantity cannot be negative."
                });

            }


            if (used > total) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Used quantity cannot be greater than total quantity."
                });

            }


            const result =
                db.prepare(`
                    INSERT INTO medicine_stock
                    (
                        medicine_name,
                        total_quantity,
                        used_quantity,
                        expiry_date
                    )
                    VALUES (?, ?, ?, ?)
                `).run(
                    medicine_name,
                    total,
                    used,
                    expiry_date || ""
                );


            res.json({
                success: true,
                message:
                    "Medicine stock saved successfully.",
                id:
                    result.lastInsertRowid
            });


        } catch (error) {

            console.error(
                "Medicine stock save error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save medicine stock."
            });

        }

    }
);


// Get medicine stock
app.get(
    "/api/medicine-stock",
    (req, res) => {

        try {

            const stocks =
                db.prepare(`
                    SELECT
                        id,
                        medicine_name,
                        total_quantity,
                        used_quantity,
                        expiry_date
                    FROM medicine_stock
                    ORDER BY id DESC
                `).all();


            res.json({
                success: true,
                stocks:
                    stocks
            });


        } catch (error) {

            console.error(
                "Medicine stock load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load medicine stock."
            });

        }

    }
);


// Delete medicine stock
app.delete(
    "/api/medicine-stock/:id",
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            const result =
                db.prepare(`
                    DELETE FROM medicine_stock
                    WHERE id = ?
                `).run(id);


            if (result.changes === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Stock record not found."
                });

            }


            res.json({
                success: true,
                message:
                    "Medicine stock deleted successfully."
            });


        } catch (error) {

            console.error(
                "Medicine stock delete error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete medicine stock."
            });

        }

    }
);


// ============================================================
// ================= REFILL REMINDER ==========================
// ============================================================

// Add refill reminder
app.post(
    "/api/refill-reminders",
    (req, res) => {

        try {

            const {
                medicine_name,
                remaining_quantity,
                refill_date,
                notes
            } = req.body;


            if (
                !medicine_name ||
                remaining_quantity === undefined ||
                !refill_date
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please fill all required fields."
                });

            }


            const remaining =
                Number(remaining_quantity);


            if (
                isNaN(remaining) ||
                remaining < 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Remaining quantity must be a valid number."
                });

            }


            const result =
                db.prepare(`
                    INSERT INTO refill_reminders
                    (
                        medicine_name,
                        remaining_quantity,
                        refill_date,
                        notes
                    )
                    VALUES (?, ?, ?, ?)
                `).run(
                    medicine_name,
                    remaining,
                    refill_date,
                    notes || ""
                );


            res.json({
                success: true,
                message:
                    "Refill reminder saved successfully.",
                id:
                    result.lastInsertRowid
            });


        } catch (error) {

            console.error(
                "Refill reminder save error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save refill reminder."
            });

        }

    }
);


// Get refill reminders
app.get(
    "/api/refill-reminders",
    (req, res) => {

        try {

            const reminders =
                db.prepare(`
                    SELECT
                        id,
                        medicine_name,
                        remaining_quantity,
                        refill_date,
                        notes
                    FROM refill_reminders
                    ORDER BY id DESC
                `).all();


            res.json({
                success: true,
                reminders:
                    reminders
            });


        } catch (error) {

            console.error(
                "Refill reminder load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load refill reminders."
            });

        }

    }
);


// Delete refill reminder
app.delete(
    "/api/refill-reminders/:id",
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            const result =
                db.prepare(`
                    DELETE FROM refill_reminders
                    WHERE id = ?
                `).run(id);


            if (result.changes === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Refill reminder not found."
                });

            }


            res.json({
                success: true,
                message:
                    "Refill reminder deleted successfully."
            });


        } catch (error) {

            console.error(
                "Refill reminder delete error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete refill reminder."
            });

        }

    }
);


// ============================================================
// ================= MEDICATION HISTORY =======================
// ============================================================

// Add medication history
app.post(
    "/api/medication-history",
    (req, res) => {

        try {

            const {
                medicine_name,
                dose,
                date,
                time,
                status,
                notes
            } = req.body;


            if (
                !medicine_name ||
                !dose ||
                !date ||
                !time ||
                !status
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please fill all required fields."
                });

            }


            const allowedStatus = [
                "Taken",
                "Missed",
                "Skipped"
            ];


            if (
                !allowedStatus.includes(status)
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid medication status."
                });

            }


            const result =
                db.prepare(`
                    INSERT INTO medication_history
                    (
                        medicine_name,
                        dose,
                        date,
                        time,
                        status,
                        notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                `).run(
                    medicine_name,
                    dose,
                    date,
                    time,
                    status,
                    notes || ""
                );


            res.json({
                success: true,
                message:
                    "Medication history saved successfully.",
                id:
                    result.lastInsertRowid
            });


        } catch (error) {

            console.error(
                "Medication history save error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to save medication history."
            });

        }

    }
);


// Get medication history
app.get(
    "/api/medication-history",
    (req, res) => {

        try {

            const history =
                db.prepare(`
                    SELECT
                        id,
                        medicine_name,
                        dose,
                        date,
                        time,
                        status,
                        notes
                    FROM medication_history
                    ORDER BY id DESC
                `).all();


            res.json({
                success: true,
                history:
                    history
            });


        } catch (error) {

            console.error(
                "Medication history load error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to load medication history."
            });

        }

    }
);


// Delete medication history
app.delete(
    "/api/medication-history/:id",
    (req, res) => {

        try {

            const id =
                Number(req.params.id);


            const result =
                db.prepare(`
                    DELETE FROM medication_history
                    WHERE id = ?
                `).run(id);


            if (result.changes === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Medication history not found."
                });

            }


            res.json({
                success: true,
                message:
                    "Medication history deleted successfully."
            });


        } catch (error) {

            console.error(
                "Medication history delete error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Unable to delete medication history."
            });

        }

    }
);

// ============================================================
// ================= PRESCRIPTION =============================
// ============================================================

// Add prescription
app.post("/api/prescriptions", (req, res) => {

    try {

        const {
            title,
            doctor_name,
            date,
            notes,
            file_data
        } = req.body;

        if (!title) {

            return res.status(400).json({
                success: false,
                message: "Prescription title is required."
            });

        }

        // Limit uploaded file data to approximately 3 MB
        if (file_data && file_data.length > 4 * 1024 * 1024) {

            return res.status(400).json({
                success: false,
                message: "File is too large. Maximum allowed size is 3 MB."
            });

        }

        const result = db.prepare(`
            INSERT INTO prescriptions
            (
                title,
                doctor_name,
                date,
                notes,
                file_data
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            title,
            doctor_name || "",
            date || "",
            notes || "",
            file_data || ""
        );

        res.json({
            success: true,
            message: "Prescription saved successfully.",
            id: result.lastInsertRowid
        });

    } catch (error) {

        console.error(
            "Prescription save error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to save prescription."
        });

    }

});


// Get prescriptions
app.get("/api/prescriptions", (req, res) => {

    try {

        const prescriptions = db.prepare(`
            SELECT
                id,
                title,
                doctor_name,
                date,
                notes,
                file_data
            FROM prescriptions
            ORDER BY id DESC
        `).all();

        res.json({
            success: true,
            prescriptions: prescriptions
        });

    } catch (error) {

        console.error(
            "Prescription load error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to load prescriptions."
        });

    }

});


// Delete prescription
app.delete("/api/prescriptions/:id", (req, res) => {

    try {

        const id = Number(req.params.id);

        const result = db.prepare(`
            DELETE FROM prescriptions
            WHERE id = ?
        `).run(id);

        if (result.changes === 0) {

            return res.status(404).json({
                success: false,
                message: "Prescription not found."
            });

        }

        res.json({
            success: true,
            message: "Prescription deleted successfully."
        });

    } catch (error) {

        console.error(
            "Prescription delete error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to delete prescription."
        });

    }

});


// ============================================================
// ================= SYMPTOM LOGGING ==========================
// ============================================================

// Add symptom
app.post("/api/symptoms", (req, res) => {

    try {

        const {
            symptom,
            date,
            severity,
            duration,
            notes
        } = req.body;

        if (!symptom || !date) {

            return res.status(400).json({
                success: false,
                message: "Symptom and date are required."
            });

        }

        const allowedSeverity = [
            "Mild",
            "Moderate",
            "Severe"
        ];

        const finalSeverity =
            allowedSeverity.includes(severity)
                ? severity
                : "Mild";

        const result = db.prepare(`
            INSERT INTO symptoms
            (
                symptom,
                date,
                severity,
                duration,
                notes
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            symptom,
            date,
            finalSeverity,
            duration || "",
            notes || ""
        );

        res.json({
            success: true,
            message: "Symptom saved successfully.",
            id: result.lastInsertRowid
        });

    } catch (error) {

        console.error(
            "Symptom save error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to save symptom."
        });

    }

});


// Get symptoms
app.get("/api/symptoms", (req, res) => {

    try {

        const symptoms = db.prepare(`
            SELECT
                id,
                symptom,
                date,
                severity,
                duration,
                notes
            FROM symptoms
            ORDER BY id DESC
        `).all();

        res.json({
            success: true,
            symptoms: symptoms
        });

    } catch (error) {

        console.error(
            "Symptom load error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to load symptoms."
        });

    }

});


// Delete symptom
app.delete("/api/symptoms/:id", (req, res) => {

    try {

        const id = Number(req.params.id);

        const result = db.prepare(`
            DELETE FROM symptoms
            WHERE id = ?
        `).run(id);

        if (result.changes === 0) {

            return res.status(404).json({
                success: false,
                message: "Symptom record not found."
            });

        }

        res.json({
            success: true,
            message: "Symptom deleted successfully."
        });

    } catch (error) {

        console.error(
            "Symptom delete error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to delete symptom."
        });

    }

});


// ============================================================
// ================= ADHERENCE ANALYTICS ======================
// ============================================================

app.get("/api/adherence-analytics", (req, res) => {

    try {

        const takenResult = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
            WHERE status = 'Taken'
        `).get();

        const missedResult = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
            WHERE status = 'Missed'
        `).get();

        const skippedResult = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
            WHERE status = 'Skipped'
        `).get();

        const totalHistoryResult = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
        `).get();

        const missedDoseResult = db.prepare(`
            SELECT COUNT(*) AS count
            FROM missed_doses
        `).get();

        const totalMedicinesResult = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medicines
        `).get();

        const totalRemindersResult = db.prepare(`
            SELECT COUNT(*) AS count
            FROM reminders
        `).get();

        const taken = Number(takenResult.count) || 0;
        const missed = Number(missedResult.count) || 0;
        const skipped = Number(skippedResult.count) || 0;
        const totalHistory = Number(totalHistoryResult.count) || 0;
        const missedDoseRecords =
            Number(missedDoseResult.count) || 0;

        const totalMedicines =
            Number(totalMedicinesResult.count) || 0;

        const totalReminders =
            Number(totalRemindersResult.count) || 0;

        let adherence = 0;

        if (totalHistory > 0) {

            adherence =
                Math.round(
                    (taken / totalHistory) * 100
                );

        }

        const medicineBreakdown =
            db.prepare(`
                SELECT
                    medicine_name,
                    COUNT(*) AS total,
                    SUM(
                        CASE
                            WHEN status = 'Taken'
                            THEN 1
                            ELSE 0
                        END
                    ) AS taken,
                    SUM(
                        CASE
                            WHEN status = 'Missed'
                            THEN 1
                            ELSE 0
                        END
                    ) AS missed
                FROM medication_history
                GROUP BY medicine_name
                ORDER BY total DESC
            `).all();

        res.json({

            success: true,

            analytics: {

                taken: taken,

                missed: missed,

                skipped: skipped,

                total: totalHistory,

                adherence: adherence,

                missedDoseRecords:
                    missedDoseRecords,

                totalMedicines:
                    totalMedicines,

                totalReminders:
                    totalReminders,

                medicineBreakdown:
                    medicineBreakdown

            }

        });

    } catch (error) {

        console.error(
            "Analytics error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to calculate adherence analytics."
        });

    }

});


// ============================================================
// ================= NOTIFICATION SYSTEM ======================
// ============================================================

// Add notification
app.post("/api/notifications", (req, res) => {

    try {

        const {
            medicine,
            message,
            date,
            time
        } = req.body;

        if (!message) {

            return res.status(400).json({
                success: false,
                message: "Notification message is required."
            });

        }

        const result = db.prepare(`
            INSERT INTO notifications
            (
                medicine,
                message,
                date,
                time,
                sent
            )
            VALUES (?, ?, ?, ?, 0)
        `).run(
            medicine || "",
            message,
            date || "",
            time || ""
        );

        res.json({
            success: true,
            message: "Notification created successfully.",
            id: result.lastInsertRowid
        });

    } catch (error) {

        console.error(
            "Notification save error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to create notification."
        });

    }

});


// Get notifications
app.get("/api/notifications", (req, res) => {

    try {

        const notifications = db.prepare(`
            SELECT
                id,
                medicine,
                message,
                date,
                time,
                sent
            FROM notifications
            ORDER BY id DESC
        `).all();

        res.json({
            success: true,
            notifications: notifications
        });

    } catch (error) {

        console.error(
            "Notification load error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to load notifications."
        });

    }

});


// Mark notification as read
app.put("/api/notifications/:id/read", (req, res) => {

    try {

        const id = Number(req.params.id);

        const result = db.prepare(`
            UPDATE notifications
            SET sent = 1
            WHERE id = ?
        `).run(id);

        if (result.changes === 0) {

            return res.status(404).json({
                success: false,
                message: "Notification not found."
            });

        }

        res.json({
            success: true,
            message: "Notification marked as read."
        });

    } catch (error) {

        console.error(
            "Notification update error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to update notification."
        });

    }

});


// Delete notification
app.delete("/api/notifications/:id", (req, res) => {

    try {

        const id = Number(req.params.id);

        const result = db.prepare(`
            DELETE FROM notifications
            WHERE id = ?
        `).run(id);

        if (result.changes === 0) {

            return res.status(404).json({
                success: false,
                message: "Notification not found."
            });

        }

        res.json({
            success: true,
            message: "Notification deleted successfully."
        });

    } catch (error) {

        console.error(
            "Notification delete error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to delete notification."
        });

    }

});


// ============================================================
// ================= AUTO NOTIFICATION ========================
// ============================================================

// Generate notifications from today's reminders
app.post("/api/notifications/generate", (req, res) => {

    try {

        const today =
            new Date().toISOString().split("T")[0];

        const reminders = db.prepare(`
            SELECT
                medicine_name,
                date,
                time,
                frequency
            FROM reminders
            WHERE date = ?
        `).all(today);

        let created = 0;

        for (const reminder of reminders) {

            const message =
                `Time to take ${reminder.medicine_name}.`;

            const existing =
                db.prepare(`
                    SELECT id
                    FROM notifications
                    WHERE medicine = ?
                    AND message = ?
                    AND date = ?
                    AND time = ?
                `).get(
                    reminder.medicine_name,
                    message,
                    reminder.date,
                    reminder.time
                );

            if (!existing) {

                db.prepare(`
                    INSERT INTO notifications
                    (
                        medicine,
                        message,
                        date,
                        time,
                        sent
                    )
                    VALUES (?, ?, ?, ?, 0)
                `).run(
                    reminder.medicine_name,
                    message,
                    reminder.date,
                    reminder.time
                );

                created++;

            }

        }

        res.json({
            success: true,
            message: `${created} notification(s) generated.`,
            created: created
        });

    } catch (error) {

        console.error(
            "Notification generation error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Unable to generate notifications."
        });

    }

});
/* =====================================================
   SYMPTOM LOGGING
===================================================== */

// ADD SYMPTOM
app.post("/api/symptoms", (req, res) => {
    try {

        const {
            symptom,
            date,
            severity,
            duration,
            notes
        } = req.body;

        if (!symptom) {
            return res.status(400).json({
                success: false,
                message: "Symptom is required"
            });
        }

        const result = db.prepare(`
            INSERT INTO symptoms
            (symptom, date, severity, duration, notes)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            symptom,
            date || "",
            severity || "",
            duration || "",
            notes || ""
        );

        res.json({
            success: true,
            message: "Symptom saved successfully",
            id: result.lastInsertRowid
        });

    } catch (error) {

        console.error("Symptom Save Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to save symptom"
        });
    }
});


// GET ALL SYMPTOMS
app.get("/api/symptoms", (req, res) => {
    try {

        const symptoms = db.prepare(`
            SELECT *
            FROM symptoms
            ORDER BY id DESC
        `).all();

        res.json({
            success: true,
            symptoms: symptoms
        });

    } catch (error) {

        console.error("Symptom Load Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load symptoms"
        });
    }
});


// DELETE SYMPTOM
app.delete("/api/symptoms/:id", (req, res) => {
    try {

        db.prepare(
            "DELETE FROM symptoms WHERE id = ?"
        ).run(req.params.id);

        res.json({
            success: true,
            message: "Symptom deleted successfully"
        });

    } catch (error) {

        console.error("Symptom Delete Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to delete symptom"
        });
    }
});
/* =====================================================
   ADHERENCE ANALYTICS
===================================================== */

app.get("/api/adherence-analytics", (req, res) => {

    try {

        const total = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
        `).get().count;

        const taken = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
            WHERE LOWER(status) = 'taken'
        `).get().count;

        const missed = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
            WHERE LOWER(status) = 'missed'
        `).get().count;

        const skipped = db.prepare(`
            SELECT COUNT(*) AS count
            FROM medication_history
            WHERE LOWER(status) = 'skipped'
        `).get().count;

        let adherenceRate = 0;

        if (total > 0) {
            adherenceRate = ((taken / total) * 100).toFixed(2);
        }

        res.json({
            success: true,

            analytics: {
                total: total,
                taken: taken,
                missed: missed,
                skipped: skipped,
                adherenceRate: Number(adherenceRate)
            }
        });

    } catch (error) {

        console.error(
            "Analytics Error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Failed to calculate adherence analytics"
        });

    }

});
/* =====================================================
   NOTIFICATION SYSTEM
===================================================== */

// ADD NOTIFICATION
app.post("/api/notifications", (req, res) => {

    try {

        const {
            medicine,
            message,
            date,
            time,
            sent
        } = req.body;

        if (!medicine || !message) {

            return res.status(400).json({
                success: false,
                message: "Medicine and message are required"
            });

        }

        const result = db.prepare(`
            INSERT INTO notifications
            (medicine, message, date, time, sent)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            medicine,
            message,
            date || "",
            time || "",
            sent || "No"
        );

        res.json({
            success: true,
            message: "Notification saved successfully",
            id: result.lastInsertRowid
        });

    } catch (error) {

        console.error("Notification Save Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to save notification"
        });

    }

});


// GET NOTIFICATIONS
app.get("/api/notifications", (req, res) => {

    try {

        const notifications = db.prepare(`
            SELECT *
            FROM notifications
            ORDER BY id DESC
        `).all();

        res.json({
            success: true,
            notifications: notifications
        });

    } catch (error) {

        console.error("Notification Load Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to load notifications"
        });

    }

});


// DELETE NOTIFICATION
app.delete("/api/notifications/:id", (req, res) => {

    try {

        db.prepare(
            "DELETE FROM notifications WHERE id = ?"
        ).run(req.params.id);

        res.json({
            success: true,
            message: "Notification deleted successfully"
        });

    } catch (error) {

        console.error("Notification Delete Error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to delete notification"
        });

    }

});


// GENERATE NOTIFICATIONS FROM REMINDERS
app.post("/api/notifications/generate", (req, res) => {

    try {

        const reminders = db.prepare(`
            SELECT *
            FROM reminders
        `).all();

        let created = 0;

        reminders.forEach(reminder => {

            const message =
                `Time to take ${reminder.medicine_name}`;

            db.prepare(`
                INSERT INTO notifications
                (medicine, message, date, time, sent)
                VALUES (?, ?, ?, ?, ?)
            `).run(
                reminder.medicine_name,
                message,
                reminder.date || "",
                reminder.time || "",
                "No"
            );

            created++;

        });

        res.json({
            success: true,
            message: `${created} notification(s) generated`
        });

    } catch (error) {

        console.error(
            "Notification Generate Error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Failed to generate notifications"
        });

    }

});
// ============================================================
// ================= SERVER START =============================
// ============================================================

const server = app.listen(
    PORT,
    () => {

        console.log(
            "----------------------------------------"
        );

        console.log(
            `Server running at http://localhost:${PORT}`
        );

        console.log(
            `Database test: http://localhost:${PORT}/api/database-test`
        );

        console.log(
            "----------------------------------------"
        );

    }
);


server.on(
    "error",
    (error) => {

        console.error(
            "SERVER ERROR:",
            error
        );

    }
);


// Keep Node process alive
setInterval(
    () => {},
    1000
);