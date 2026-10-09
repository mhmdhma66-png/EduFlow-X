const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured");
}
// ================================
// Student profile migration
// ================================
const studentColumns = db.prepare("PRAGMA table_info(students)").all();

if (!studentColumns.some(c => c.name === "photo")) {
    db.exec("ALTER TABLE students ADD COLUMN photo TEXT DEFAULT ''");
}

if (!studentColumns.some(c => c.name === "notes")) {
    db.exec("ALTER TABLE students ADD COLUMN notes TEXT DEFAULT ''");
}

// ================================
// Middleware
// ================================
app.use(cors());
app.use(express.json({ limit: "5mb" }));

// ================================
// Authentication
// ================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            success: false,
            message: "غير مصرح لك بالدخول"
        });
    }

    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
        return res.status(401).json({
            success: false,
            message: "Token غير صحيح"
        });
    }

    try {
        const decoded = jwt.verify(parts[1], JWT_SECRET);

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message: "الجلسة انتهت أو Token غير صالح"
        });
    }
}
  
// ================================
// Admin Authorization
// ================================
function requireAdmin(req, res, next) {
    const admin = db.prepare(`
        SELECT id, role
        FROM teachers
        WHERE id = ?
    `).get(req.user.id);

    if (!admin || admin.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "غير مصرح لك بالدخول إلى لوحة الإدارة"
        });
    }

    next();
}

// ================================
// ADMIN - TEST
// ================================
app.get("/api/admin/test", authenticateToken, requireAdmin, (req, res) => {
    res.json({
        success: true,
        message: "Admin access granted 👑"
    });
});

// ================================
// Home
// ================================
app.get("/", (req, res) => {

    res.json({
        success: true,
        message: "EduFlow X Backend is running 🚀"
    });

});

// ================================
// AUTH - REGISTER
// ================================
app.post("/api/auth/register", async (req, res) => {

    try {

        const {
            name,
            email,
            phone,
            password
        } = req.body;

        if (!name || !email || !password) {

            return res.status(400).json({
                success: false,
                message: "الاسم والإيميل وكلمة السر مطلوبين"
            });

        }

        const cleanEmail = email.trim().toLowerCase();

        const existingTeacher = db.prepare(`
            SELECT id
            FROM teachers
            WHERE email = ?
        `).get(cleanEmail);

        if (existingTeacher) {

            return res.status(409).json({
                success: false,
                message: "الإيميل مستخدم بالفعل"
            });

        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const result = db.prepare(`
            INSERT INTO teachers
            (name, email, phone, password)
            VALUES (?, ?, ?, ?)
        `).run(
            name.trim(),
            cleanEmail,
            phone || "",
            hashedPassword
        );

        const teacher = db.prepare(`
            SELECT
                id,
                name,
                email,
                phone,
                role,
                created_at
            FROM teachers
            WHERE id = ?
        `).get(result.lastInsertRowid);

        const token = jwt.sign(
            {
                id: teacher.id,
                email: teacher.email,
                role: teacher.role
            },
            JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        res.status(201).json({

            success: true,

            message: "تم إنشاء حساب المدرس بنجاح 🎉",

            token,

            teacher

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: "حدث خطأ في السيرفر"
        });

    }

});

// ================================
// AUTH - LOGIN
// ================================
app.post("/api/auth/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;

        if (!email || !password) {

            return res.status(400).json({
                success: false,
                message: "الإيميل وكلمة السر مطلوبين"
            });

        }

        const cleanEmail = email.trim().toLowerCase();

        const teacher = db.prepare(`
            SELECT *
            FROM teachers
            WHERE email = ?
        `).get(cleanEmail);

        if (!teacher) {

            return res.status(401).json({
                success: false,
                message: "الإيميل أو كلمة السر غير صحيحة"
            });

        }

        const passwordCorrect =
            await bcrypt.compare(password, teacher.password);

        if (!passwordCorrect) {

            return res.status(401).json({
                success: false,
                message: "الإيميل أو كلمة السر غير صحيحة"
            });

        }

        const token = jwt.sign(
            {
                id: teacher.id,
                email: teacher.email,
                role: teacher.role
            },
            JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        delete teacher.password;

        res.json({

            success: true,

            message: "تم تسجيل الدخول بنجاح 🎉",

            token,

            teacher

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: "حدث خطأ في السيرفر"
        });

    }

});

// ================================
// AUTH - ME
// ================================
app.get(
    "/api/auth/me",
    authenticateToken,
    (req, res) => {

        const teacher = db.prepare(`
            SELECT
                id,
                name,
                email,
                phone,
                role,
                created_at
            FROM teachers
            WHERE id = ?
        `).get(req.user.id);

        if (!teacher) {

            return res.status(404).json({
                success: false,
                message: "المدرس غير موجود"
            });

        }

        res.json({
            success: true,
            teacher
        });

    }
);

// ================================
// DASHBOARD
// ================================
app.get(
    "/api/dashboard",
    authenticateToken,
    (req, res) => {

        const studentsCount = db.prepare(`
            SELECT COUNT(*) AS count
            FROM students
            WHERE teacher_id = ?
        `).get(req.user.id).count;

        const gradesCount = db.prepare(`
            SELECT COUNT(*) AS count
            FROM grades g
            JOIN students s
                ON g.student_id = s.id
            WHERE s.teacher_id = ?
        `).get(req.user.id).count;

        const attendanceCount = db.prepare(`
            SELECT COUNT(*) AS count
            FROM attendance a
            JOIN students s
                ON a.student_id = s.id
            WHERE s.teacher_id = ?
        `).get(req.user.id).count;

        res.json({

            success: true,

            teacher_id: req.user.id,

            students: studentsCount,

            grades: gradesCount,

            attendance: attendanceCount

        });

    }
);

// ================================
// STUDENTS - GET
// ================================
app.get(
    "/api/students",
    authenticateToken,
    (req, res) => {

        const students = db.prepare(`
            SELECT
                id,
                name,
                phone,
                parent_phone,
                grade,
                class_name,
                photo,
                notes,
                created_at
            FROM students
            WHERE teacher_id = ?
            ORDER BY id DESC
        `).all(req.user.id);

        res.json({

            success: true,

            students

        });

    }
);

// ================================
// STUDENTS - CREATE
// ================================
app.post(
    "/api/students",
    authenticateToken,
    (req, res) => {

        try {

            const {
                name,
                phone,
                parent_phone,
                grade,
                class_name,
                photo,
                notes
            } = req.body;

            if (!name) {

                return res.status(400).json({
                    success: false,
                    message: "اسم الطالب مطلوب"
                });

            }

            const result = db.prepare(`
                INSERT INTO students
                (
                    teacher_id,
                    name,
                    phone,
                    parent_phone,
                    grade,
                    class_name,
                    photo,
                    notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).run(

                req.user.id,

                name.trim(),

                phone || "",

                parent_phone || "",

                grade || "",

                class_name || "",

                photo || "",

                notes || ""

            );

            const student = db.prepare(`
                SELECT *
                FROM students
                WHERE id = ?
            `).get(result.lastInsertRowid);

            res.status(201).json({

                success: true,

                message: "تم إضافة الطالب بنجاح 🎉",

                student

            });

        } catch (error) {

            console.error(error);

            res.status(500).json({

                success: false,

                message: "حدث خطأ أثناء إضافة الطالب"

            });

        }

    }
);

// ================================
// STUDENTS - UPDATE
// ================================
app.put(
    "/api/students/:id",
    authenticateToken,
    (req, res) => {

        const studentId = Number(req.params.id);

        const student = db.prepare(`
            SELECT id
            FROM students
            WHERE id = ?
            AND teacher_id = ?
        `).get(
            studentId,
            req.user.id
        );

        if (!student) {

            return res.status(404).json({
                success: false,
                message: "الطالب غير موجود"
            });

        }

        const {
            name,
            phone,
            parent_phone,
            grade,
            class_name,
            photo,
            notes
        } = req.body;

        if (!name) {

            return res.status(400).json({
                success: false,
                message: "اسم الطالب مطلوب"
            });

        }

        db.prepare(`
            UPDATE students
            SET
                name = ?,
                phone = ?,
                parent_phone = ?,
                grade = ?,
                class_name = ?,
                photo = ?,
                notes = ?
            WHERE id = ?
            AND teacher_id = ?
        `).run(

            name.trim(),

            phone || "",

            parent_phone || "",

            grade || "",

            class_name || "",

            photo || "",

            notes || "",

            studentId,

            req.user.id

        );

        const updatedStudent = db.prepare(`
            SELECT *
            FROM students
            WHERE id = ?
        `).get(studentId);

        res.json({

            success: true,

            message: "تم تعديل بيانات الطالب ✓",

            student: updatedStudent

        });

    }
);

// ================================
// STUDENTS - DELETE
// ================================
app.delete(
    "/api/students/:id",
    authenticateToken,
    (req, res) => {

        const studentId = Number(req.params.id);

        const result = db.prepare(`
            DELETE FROM students
            WHERE id = ?
            AND teacher_id = ?
        `).run(

            studentId,

            req.user.id

        );

        if (result.changes === 0) {

            return res.status(404).json({

                success: false,

                message: "الطالب غير موجود"

            });

        }

        res.json({

            success: true,

            message: "تم حذف الطالب وكل بياناته المرتبطة ✓"

        });

    }
);
// ================================
// ATTENDANCE - GET
// ================================
app.get(
    "/api/attendance",
    authenticateToken,
    (req, res) => {

        const date = req.query.date;
        const scheduleId = req.query.schedule_id;

        let attendance;

        if (date && scheduleId) {

            attendance = db.prepare(`
                SELECT
                    a.id,
                    a.student_id,
                    a.schedule_id,
                    a.date,
                    a.status,
                    a.notes
                FROM attendance a
                JOIN students s
                    ON a.student_id = s.id
                WHERE s.teacher_id = ?
                AND a.date = ?
                AND a.schedule_id = ?
                ORDER BY s.name
            `).all(
                req.user.id,
                date,
                scheduleId
            );

        } else if (date) {

            attendance = db.prepare(`
                SELECT
                    a.id,
                    a.student_id,
                    a.schedule_id,
                    a.date,
                    a.status,
                    a.notes
                FROM attendance a
                JOIN students s
                    ON a.student_id = s.id
                WHERE s.teacher_id = ?
                AND a.date = ?
                ORDER BY s.name
            `).all(
                req.user.id,
                date
            );

        } else {

            attendance = db.prepare(`
                SELECT
                    a.id,
                    a.student_id,
                    a.schedule_id,
                    a.date,
                    a.status,
                    a.notes
                FROM attendance a
                JOIN students s
                    ON a.student_id = s.id
                WHERE s.teacher_id = ?
                ORDER BY a.date DESC
            `).all(
                req.user.id
            );

        }

        res.json({
            success: true,
            attendance
        });

    }
);
// ================================
// ATTENDANCE - SAVE
// ================================
app.post(
    "/api/attendance",
    authenticateToken,
    (req, res) => {

        try {

            const {
                student_id,
                schedule_id,
                date,
                status,
                notes
            } = req.body;

            if (!student_id || !schedule_id || !date || !status) {

                return res.status(400).json({
                    success: false,
                    message: "بيانات الحضور ناقصة"
                });

            }

            // التأكد أن الطالب تابع للمدرس
            const student = db.prepare(`
                SELECT id
                FROM students
                WHERE id = ?
                AND teacher_id = ?
            `).get(
                student_id,
                req.user.id
            );

            if (!student) {

                return res.status(404).json({
                    success: false,
                    message: "الطالب غير موجود"
                });

            }

            // التأكد أن الحصة تابعة للمدرس
            const schedule = db.prepare(`
                SELECT id
                FROM schedule
                WHERE id = ?
                AND teacher_id = ?
            `).get(
                schedule_id,
                req.user.id
            );

            if (!schedule) {

                return res.status(404).json({
                    success: false,
                    message: "الحصة غير موجودة"
                });

            }

            // التأكد أن الطالب مشترك في الحصة
            const studentClass = db.prepare(`
                SELECT id
                FROM student_classes
                WHERE student_id = ?
                AND schedule_id = ?
            `).get(
                student_id,
                schedule_id
            );

            if (!studentClass) {

                return res.status(400).json({
                    success: false,
                    message: "الطالب غير مشترك في هذه الحصة"
                });

            }

            // البحث عن حضور نفس الطالب في نفس الحصة ونفس اليوم
            const existing = db.prepare(`
                SELECT id
                FROM attendance
                WHERE student_id = ?
                AND schedule_id = ?
                AND date = ?
            `).get(
                student_id,
                schedule_id,
                date
            );

            if (existing) {

                db.prepare(`
                    UPDATE attendance
                    SET
                        status = ?,
                        notes = ?
                    WHERE id = ?
                `).run(
                    status,
                    notes || "",
                    existing.id
                );

            } else {

                db.prepare(`
                    INSERT INTO attendance
                    (
                        student_id,
                        schedule_id,
                        date,
                        status,
                        notes
                    )
                    VALUES (?, ?, ?, ?, ?)
                `).run(
                    student_id,
                    schedule_id,
                    date,
                    status,
                    notes || ""
                );

            }

            res.json({
                success: true,
                message: "تم حفظ الحضور ✓"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "حدث خطأ أثناء حفظ الحضور"
            });

        }

    }
);
// ================================
// GRADES - GET
// ================================
app.get(
    "/api/grades",
    authenticateToken,
    (req, res) => {

        const grades = db.prepare(`
            SELECT
                g.id,
                g.student_id,
                s.name AS student_name,
                g.subject,
                g.exam_name,
                g.score,
                g.max_score,
                g.created_at
            FROM grades g
            JOIN students s
                ON g.student_id = s.id
            WHERE s.teacher_id = ?
            ORDER BY g.id DESC
        `).all(req.user.id);

        res.json({

            success: true,

            grades

        });

    }
);

// ================================
// GRADES - CREATE
// ================================
app.post(
    "/api/grades",
    authenticateToken,
    (req, res) => {

        const {
            student_id,
            subject,
            exam_name,
            score,
            max_score
        } = req.body;

        if (
            !student_id ||
            !exam_name ||
            score === undefined
        ) {

            return res.status(400).json({

                success: false,

                message: "بيانات الدرجة ناقصة"

            });

        }

        const student = db.prepare(`
            SELECT id
            FROM students
            WHERE id = ?
            AND teacher_id = ?
        `).get(

            student_id,

            req.user.id

        );

        if (!student) {

            return res.status(404).json({

                success: false,

                message: "الطالب غير موجود"

            });

        }

        const result = db.prepare(`
            INSERT INTO grades
            (
                student_id,
                subject,
                exam_name,
                score,
                max_score
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(

            student_id,

            subject || "",

            exam_name,

            Number(score),

            max_score === undefined
                ? 100
                : Number(max_score)

        );

        const grade = db.prepare(`
            SELECT *
            FROM grades
            WHERE id = ?
        `).get(result.lastInsertRowid);

        res.status(201).json({

            success: true,

            message: "تم حفظ الدرجة ✓",

            grade

        });

    }
);

// ================================
// GRADES - DELETE
// ================================
app.delete(
    "/api/grades/:id",
    authenticateToken,
    (req, res) => {

        const gradeId = Number(req.params.id);

        const result = db.prepare(`
            DELETE FROM grades
            WHERE id = ?
            AND student_id IN (
                SELECT id
                FROM students
                WHERE teacher_id = ?
            )
        `).run(

            gradeId,

            req.user.id

        );

        if (result.changes === 0) {

            return res.status(404).json({

                success: false,

                message: "الدرجة غير موجودة"

            });

        }

        res.json({

            success: true,

            message: "تم حذف الدرجة ✓"

        });

    }
);

// ================================
// SCHEDULE - GET
// ================================
app.get(
    "/api/schedule",
    authenticateToken,
    (req, res) => {

        const schedule = db.prepare(`
            SELECT
                id,
                day,
                time,
                subject,
                class_name
            FROM schedule
            WHERE teacher_id = ?
            ORDER BY id DESC
        `).all(req.user.id);

        res.json({

            success: true,

            schedule

        });

    }
);

// ================================
// SCHEDULE - CREATE
// ================================
app.post(
    "/api/schedule",
    authenticateToken,
    (req, res) => {

        const {
            day,
            time,
            subject,
            class_name
        } = req.body;

        if (!day || !time || !subject) {

            return res.status(400).json({

                success: false,

                message: "اليوم والوقت والمادة مطلوبين"

            });

        }

        const result = db.prepare(`
            INSERT INTO schedule
            (
                teacher_id,
                day,
                time,
                subject,
                class_name
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(

            req.user.id,

            day,

            time,

            subject,

            class_name || ""

        );

        const schedule = db.prepare(`
            SELECT *
            FROM schedule
            WHERE id = ?
        `).get(result.lastInsertRowid);

        res.status(201).json({

            success: true,

            message: "تم إضافة الحصة ✓",

            schedule

        });

    }
);

// ================================
// SCHEDULE - DELETE
// ================================
app.delete(
    "/api/schedule/:id",
    authenticateToken,
    (req, res) => {

        const scheduleId = Number(req.params.id);

        const result = db.prepare(`
            DELETE FROM schedule
            WHERE id = ?
            AND teacher_id = ?
        `).run(

            scheduleId,

            req.user.id

        );

        if (result.changes === 0) {

            return res.status(404).json({

                success: false,

                message: "الحصة غير موجودة"

            });

        }

        res.json({

            success: true,

            message: "تم حذف الحصة ✓"

        });

    }
);
// ========================================
// STUDENT CLASSES
// ========================================

app.post("/api/student-classes", authenticateToken, (req, res) => {
    try {
        const { student_id, schedule_id } = req.body;

        if (!student_id || !schedule_id) {
            return res.status(400).json({
                success: false,
                message: "الطالب والحصة مطلوبين"
            });
        }

        const student = db.prepare(`
            SELECT id
            FROM students
            WHERE id = ?
            AND teacher_id = ?
        `).get(student_id, req.user.id);

        if (!student) {
            return res.status(404).json({
                success: false,
                message: "الطالب غير موجود"
            });
        }

        const schedule = db.prepare(`
            SELECT id
            FROM schedule
            WHERE id = ?
            AND teacher_id = ?
        `).get(schedule_id, req.user.id);

        if (!schedule) {
            return res.status(404).json({
                success: false,
                message: "الحصة غير موجودة"
            });
        }

        db.prepare(`
            INSERT INTO student_classes
            (student_id, schedule_id)
            VALUES (?, ?)
        `).run(student_id, schedule_id);

        res.status(201).json({
            success: true,
            message: "تم إضافة الطالب للحصة ✓"
        });

    } catch (error) {

        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).json({
                success: false,
                message: "الطالب موجود بالفعل في هذه الحصة"
            });
        }

        console.error(error);

        res.status(500).json({
            success: false,
            message: "حدث خطأ أثناء إضافة الطالب للحصة"
        });
    }
});

app.get("/api/student-classes/:studentId", authenticateToken, (req, res) => {

    const studentId = Number(req.params.studentId);

    const classes = db.prepare(`
        SELECT
            sc.id,
            sc.student_id,
            sc.schedule_id,
            s.day,
            s.time,
            s.subject,
            s.class_name
        FROM student_classes sc
        JOIN schedule s
            ON sc.schedule_id = s.id
        JOIN students st
            ON sc.student_id = st.id
        WHERE sc.student_id = ?
        AND st.teacher_id = ?
        AND s.teacher_id = ?
        ORDER BY s.id DESC
    `).all(
        studentId,
        req.user.id,
        req.user.id
    );

    res.json({
        success: true,
        classes
    });
});

app.get("/api/schedule/:scheduleId/students", authenticateToken, (req, res) => {

    const scheduleId = Number(req.params.scheduleId);

    const students = db.prepare(`
        SELECT
            st.id,
            st.name,
            st.phone,
            st.parent_phone,
            st.grade,
            st.class_name,
            st.photo,
            st.notes
        FROM student_classes sc
        JOIN students st
            ON sc.student_id = st.id
        JOIN schedule s
            ON sc.schedule_id = s.id
        WHERE sc.schedule_id = ?
        AND st.teacher_id = ?
        AND s.teacher_id = ?
        ORDER BY st.name
    `).all(
        scheduleId,
        req.user.id,
        req.user.id
    );

    res.json({
        success: true,
        students
    });
});

app.delete("/api/student-classes/:id", authenticateToken, (req, res) => {

    const id = Number(req.params.id);

    const result = db.prepare(`
        DELETE FROM student_classes
        WHERE id = ?
        AND student_id IN (
            SELECT id
            FROM students
            WHERE teacher_id = ?
        )
    `).run(id, req.user.id);

    if (result.changes === 0) {
        return res.status(404).json({
            success: false,
            message: "الطالب غير مشترك في هذه الحصة"
        });
    }

    res.json({
        success: true,
        message: "تم إزالة الطالب من الحصة ✓"
    });
});

// ========================================
// ADMIN API - protected by database role
// ========================================
db.exec(`
CREATE TABLE IF NOT EXISTS site_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

app.get("/api/admin/overview", authenticateToken, requireAdmin, (req, res) => {
  const teachers = db.prepare("SELECT COUNT(*) AS count FROM teachers").get().count;
  const students = db.prepare("SELECT COUNT(*) AS count FROM students").get().count;
  const subscriptions = db.prepare("SELECT COUNT(*) AS count FROM subscriptions WHERE status IN ('active','trial')").get().count;
  const activeSubscriptions = db.prepare("SELECT COUNT(*) AS count FROM subscriptions WHERE status='active'").get().count;
  res.json({ success: true, teachers, students, subscriptions, activeSubscriptions });
});

app.get("/api/admin/teachers", authenticateToken, requireAdmin, (req, res) => {
  const teachers = db.prepare(`
    SELECT t.id, t.name, t.email, t.phone, t.role, t.created_at,
           s.plan AS subscription_plan, s.status AS subscription_status,
           s.start_date AS subscription_start, s.end_date AS subscription_end,
           s.payment_reference AS payment_reference
    FROM teachers t
    LEFT JOIN subscriptions s ON s.teacher_id = t.id
    ORDER BY t.id DESC
  `).all();
  res.json({ success: true, teachers });
});

app.patch("/api/admin/teachers/:id/role", authenticateToken, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const role = req.body?.role;
  if (!Number.isInteger(id) || id <= 0 || !["teacher", "admin"].includes(role)) {
    return res.status(400).json({ success: false, message: "بيانات غير صحيحة" });
  }
  if (id === Number(req.user.id) && role !== "admin") {
    return res.status(400).json({ success: false, message: "لا يمكنك إزالة صلاحية الأدمن من حسابك الحالي" });
  }
  const result = db.prepare("UPDATE teachers SET role = ? WHERE id = ?").run(role, id);
  if (!result.changes) return res.status(404).json({ success: false, message: "الحساب غير موجود" });
  res.json({ success: true, message: "تم تحديث صلاحية الحساب" });
});

app.put("/api/admin/teachers/:id/subscription", authenticateToken, requireAdmin, (req, res) => {
  const teacherId = Number(req.params.id);
  const { plan = "monthly", status = "active", start_date = null, end_date = null, payment_reference = "" } = req.body || {};
  if (!Number.isInteger(teacherId) || teacherId <= 0) return res.status(400).json({ success: false, message: "رقم الحساب غير صحيح" });
  if (!["trial", "monthly", "yearly", "lifetime"].includes(plan)) return res.status(400).json({ success: false, message: "نوع الاشتراك غير صحيح" });
  if (!["trial", "active", "expired", "cancelled", "pending"].includes(status)) return res.status(400).json({ success: false, message: "حالة الاشتراك غير صحيحة" });
  const teacher = db.prepare("SELECT id FROM teachers WHERE id = ?").get(teacherId);
  if (!teacher) return res.status(404).json({ success: false, message: "المدرس غير موجود" });
  db.prepare(`
    INSERT INTO subscriptions (teacher_id, plan, status, start_date, end_date, payment_reference)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(teacher_id) DO UPDATE SET
      plan=excluded.plan, status=excluded.status, start_date=excluded.start_date,
      end_date=excluded.end_date, payment_reference=excluded.payment_reference
  `).run(teacherId, plan, status, start_date || null, end_date || null, String(payment_reference || "").slice(0, 200));
  res.json({ success: true, message: "تم تحديث الاشتراك بنجاح" });
});

app.get("/api/admin/students", authenticateToken, requireAdmin, (req, res) => {
  const students = db.prepare(`
    SELECT s.id, s.name, s.phone, s.parent_phone, s.grade, s.class_name, s.created_at,
           t.id AS teacher_id, t.name AS teacher_name, t.email AS teacher_email
    FROM students s
    LEFT JOIN teachers t ON t.id = s.teacher_id
    ORDER BY s.id DESC
  `).all();
  res.json({ success: true, students });
});

app.get("/api/admin/settings", authenticateToken, requireAdmin, (req, res) => {
  const settings = db.prepare("SELECT key, value, updated_at FROM site_settings ORDER BY key").all();
  res.json({ success: true, settings });
});

app.put("/api/admin/settings", authenticateToken, requireAdmin, (req, res) => {
  const entries = req.body?.settings;
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) {
    return res.status(400).json({ success: false, message: "الإعدادات غير صحيحة" });
  }
  const allowed = new Set(["site_name", "support_email", "support_phone", "announcement", "trial_days"]);
  const save = db.prepare(`
    INSERT INTO site_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP
  `);
  const tx = db.transaction(() => {
    for (const [key, value] of Object.entries(entries)) {
      if (allowed.has(key)) save.run(key, String(value ?? "").slice(0, 1000));
    }
  });
  tx();
  res.json({ success: true, message: "تم حفظ إعدادات الموقع" });
});

// ================================
// START SERVER
// ================================


app.listen(PORT, "0.0.0.0", () => {
    console.log("==============================");
    console.log("EduFlow X Backend 🚀");
    console.log(`Server: http://localhost:${PORT}`);
    console.log("Database: Connected 🗄️");
    console.log("==============================");

});