const Database = require("better-sqlite3");

const db = new Database("eduflow.db");

db.pragma("foreign_keys = ON");

// ================================
// Teachers
// ================================
db.exec(`
CREATE TABLE IF NOT EXISTS teachers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'teacher',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// ========================================
// إصلاح قواعد البيانات القديمة تلقائيًا
// ========================================
const teacherColumns = db
    .prepare("PRAGMA table_info(teachers)")
    .all();

const hasRoleColumn = teacherColumns.some(
    column => column.name === "role"
);

if (!hasRoleColumn) {
    db.exec(`
        ALTER TABLE teachers
        ADD COLUMN role TEXT NOT NULL DEFAULT 'teacher'
    `);

    console.log("✅ تم إضافة عمود role إلى قاعدة البيانات");
}

// ================================
// Students
// ================================
db.exec(`
CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    phone TEXT,
    parent_phone TEXT,
    grade TEXT,
    class_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (teacher_id)
    REFERENCES teachers(id)
    ON DELETE CASCADE
);
`);

// ================================
// Attendance
// ================================
db.exec(`
CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL,
    notes TEXT,

    FOREIGN KEY (student_id)
    REFERENCES students(id)
    ON DELETE CASCADE
);
`);

// ================================
// Grades
// ================================
db.exec(`
CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    subject TEXT,
    exam_name TEXT,
    score REAL,
    max_score REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
    REFERENCES students(id)
    ON DELETE CASCADE
);
`);

// ================================
// Schedule
// ================================
db.exec(`
CREATE TABLE IF NOT EXISTS schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    time TEXT NOT NULL,
    subject TEXT,
    class_name TEXT,

    FOREIGN KEY (teacher_id)
    REFERENCES teachers(id)
    ON DELETE CASCADE
);
`);
// ========================================
// Attendance Migration
// إضافة ربط الحضور بالحصة
// ========================================
const attendanceColumns = db
    .prepare("PRAGMA table_info(attendance)")
    .all();

const hasScheduleId = attendanceColumns.some(
    column => column.name === "schedule_id"
);

if (!hasScheduleId) {
    db.exec(`
        ALTER TABLE attendance
        ADD COLUMN schedule_id INTEGER
    `);

    console.log("✅ تم إضافة schedule_id إلى الحضور");
}
// ========================================
// Student Classes
// ربط الطلاب بالحصص
// ========================================
db.exec(`
CREATE TABLE IF NOT EXISTS student_classes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    schedule_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id)
    REFERENCES students(id)
    ON DELETE CASCADE,

    FOREIGN KEY (schedule_id)
    REFERENCES schedule(id)
    ON DELETE CASCADE,

    UNIQUE(student_id, schedule_id)
);
`);

console.log("EduFlow X Database is ready 🗄️");

module.exports = db;