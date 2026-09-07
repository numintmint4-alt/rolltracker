const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const xlsx = require('xlsx');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// สร้างโฟลเดอร์ uploads (ป้องกัน error)
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your-secret-key-change-me';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ---------- Database ----------
const db = new sqlite3.Database('./rolls.db', (err) => {
    if (err) console.error('Database error:', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    // Users
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Rolls
    db.run(`CREATE TABLE IF NOT EXISTS rolls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_number TEXT UNIQUE,
        grade TEXT,
        width TEXT,
        supplier TEXT,
        supplier_grade TEXT,
        supplier_sn TEXT,
        dimeter TEXT,
        kgs TEXT,
        meter TEXT,
        supplier_doc_no TEXT,
        buy_date TEXT,
        ageing TEXT,
        qlt TEXT,
        customer TEXT,
        comp_no TEXT,
        loc TEXT,
        status TEXT,
        note TEXT,
        group_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Import history
    db.run(`CREATE TABLE IF NOT EXISTS import_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        imported_by TEXT,
        rows_imported INTEGER,
        import_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Stock count settings
    db.run(`CREATE TABLE IF NOT EXISTS stock_counts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        count_number TEXT,
        stock_date TEXT,
        stock_time TEXT,
        created_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Stock check items
    db.run(`CREATE TABLE IF NOT EXISTS stock_check_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stock_count_id INTEGER,
        roll_number TEXT,
        checked_by TEXT,
        found INTEGER DEFAULT 0,
        checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Default users
    const adminUser = 'admin';
    const adminPass = bcrypt.hashSync('admin123', 10);
    db.get(`SELECT id FROM users WHERE username = ?`, [adminUser], (err, row) => {
        if (!row) {
            db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')`, [adminUser, adminPass]);
            console.log('✅ Created default admin: admin / admin123');
        }
    });
    const userUser = 'user';
    const userPass = bcrypt.hashSync('user123', 10);
    db.get(`SELECT id FROM users WHERE username = ?`, [userUser], (err, row) => {
        if (!row) {
            db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'user')`, [userUser, userPass]);
            console.log('✅ Created default user: user / user123');
        }
    });
});

// ---------- Middleware ----------
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (e) {
        res.status(401).json({ message: 'Invalid token' });
    }
}

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
    next();
}

// ---------- Helper: แปลงวันที่จาก Excel ----------
function convertExcelDate(value) {
    if (!value) return '';
    // ถ้าเป็นตัวเลข (Excel Serial Date)
    if (typeof value === 'number') {
        const epoch = new Date(1899, 11, 30);
        const d = new Date(epoch.getTime() + value * 86400000);
        return d.toLocaleDateString('th-TH', { year: 'numeric', month: 'numeric', day: 'numeric' });
    }
    // ถ้าเป็น string แล้ว ให้ตัดทิ้งเวลา (ถ้ามี)
    if (typeof value === 'string') {
        const parts = value.split('T');
        return parts[0].split(' ')[0];
    }
    return String(value);
}

// ---------- Auth Routes ----------
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Missing credentials' });
    db.get(`SELECT * FROM users WHERE username = ? AND is_active = 1`, [username], (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Invalid credentials' });
        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1d' });
        res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    db.get(`SELECT id, username, role FROM users WHERE id = ?`, [req.user.id], (err, user) => {
        if (err || !user) return res.status(404).json({ message: 'User not found' });
        res.json({ user });
    });
});

app.post('/api/auth/register', authMiddleware, adminMiddleware, (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Missing fields' });
    const hashed = bcrypt.hashSync(password, 10);
    db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashed, role || 'user'], function(err) {
        if (err) return res.status(400).json({ message: 'Username already exists' });
        res.json({ ok: true, id: this.lastID });
    });
});

// ---------- User Management ----------
app.get('/api/users', authMiddleware, adminMiddleware, (req, res) => {
    db.all(`SELECT id, username, role, is_active, created_at FROM users`, (err, rows) => {
        if (err) return res.status(500).json({ message: 'DB error' });
        res.json({ users: rows });
    });
});

app.put('/api/users/:id/toggle', authMiddleware, adminMiddleware, (req, res) => {
    const { is_active } = req.body;
    db.run(`UPDATE users SET is_active = ? WHERE id = ?`, [is_active ? 1 : 0, req.params.id], function(err) {
        if (err) return res.status(500).json({ message: 'Update failed' });
        res.json({ ok: true });
    });
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, (req, res) => {
    db.run(`DELETE FROM users WHERE id = ? AND role != 'admin'`, [req.params.id], function(err) {
        if (err || this.changes === 0) return res.status(400).json({ message: 'Cannot delete admin or user not found' });
        res.json({ ok: true });
    });
});

// ---------- Rolls ----------
app.get('/api/rolls/search', authMiddleware, (req, res) => {
    const q = req.query.q || '';
    db.get(`SELECT * FROM rolls WHERE roll_number = ?`, [q], (err, roll) => {
        if (err) return res.status(500).json({ message: 'DB error' });
        if (!roll) return res.status(404).json({ message: 'Not found' });
        // แปลง buy_date ก่อนส่งกลับ
        if (roll.buy_date) roll.buy_date = convertExcelDate(roll.buy_date);
        res.json({ roll });
    });
});

app.get('/api/rolls/suggest', authMiddleware, (req, res) => {
    const q = req.query.q || '';
    if (q.length < 1) return res.json([]);
    db.all(`SELECT roll_number FROM rolls WHERE roll_number LIKE ? ESCAPE '\\' LIMIT 20`, [`%${q.replace(/%/g,'\\%')}%`], (err, rows) => {
        if (err) return res.status(500).json([]);
        res.json(rows.map(r => r.roll_number));
    });
});

app.get('/api/rolls/count', authMiddleware, (req, res) => {
    db.get(`SELECT COUNT(*) as count FROM rolls`, (err, row) => {
        res.json({ count: row ? row.count : 0 });
    });
});

app.get('/api/dashboard/stats', authMiddleware, (req, res) => {
    let stats = { total: 0, loc1: 0, locf: 0, full: 0, scrap: 0, wait: 0 };
    db.get(`SELECT COUNT(*) as total FROM rolls`, (err, row) => { stats.total = row.total; });
    db.get(`SELECT COUNT(*) as loc1 FROM rolls WHERE loc = 'LOC1'`, (err, row) => { stats.loc1 = row.loc1; });
    db.get(`SELECT COUNT(*) as locf FROM rolls WHERE loc = 'LOCF'`, (err, row) => { stats.locf = row.locf; });
    db.get(`SELECT COUNT(*) as full FROM rolls WHERE status = 'เต็ม'`, (err, row) => { stats.full = row.full; });
    db.get(`SELECT COUNT(*) as scrap FROM rolls WHERE status = 'เศษ'`, (err, row) => { stats.scrap = row.scrap; });
    db.get(`SELECT COUNT(*) as wait FROM rolls WHERE status = 'รอกรอ'`, (err, row) => { stats.wait = row.wait; });
    setTimeout(() => {
        res.json({
            total: stats.total || 0,
            by_loc: { LOC1: stats.loc1 || 0, LOCF: stats.locf || 0 },
            by_status: { 'เต็ม': stats.full || 0, 'เศษ': stats.scrap || 0, 'รอกรอ': stats.wait || 0 }
        });
    }, 200);
});

// ---------- Stock Settings ----------
app.post('/api/stock/settings', authMiddleware, adminMiddleware, (req, res) => {
    const { count_number, stock_date, stock_time } = req.body;
    if (!count_number || !stock_date || !stock_time) {
        return res.status(400).json({ message: 'Missing fields' });
    }
    db.run(`INSERT INTO stock_counts (count_number, stock_date, stock_time, created_by) VALUES (?, ?, ?, ?)`,
        [count_number, stock_date, stock_time, req.user.username],
        function(err) {
            if (err) return res.status(500).json({ message: 'Failed to save settings' });
            res.json({ ok: true, id: this.lastID });
        });
});

app.get('/api/stock/latest', authMiddleware, (req, res) => {
    db.get(`SELECT * FROM stock_counts ORDER BY id DESC LIMIT 1`, (err, row) => {
        if (err || !row) return res.status(404).json({ message: 'No settings found' });
        res.json(row);
    });
});

// ---------- Stock Check ----------
app.get('/api/stock/check-items', authMiddleware, (req, res) => {
    db.get(`SELECT id FROM stock_counts ORDER BY id DESC LIMIT 1`, (err, row) => {
        if (err || !row) {
            return res.status(404).json({ message: 'No stock count settings' });
        }
        const stockCountId = row.id;
        db.all(`SELECT r.*, 
                       (SELECT found FROM stock_check_items WHERE stock_count_id = ? AND roll_number = r.roll_number AND checked_by = ?) as found
                FROM rolls r ORDER BY r.group_name, r.width`, [stockCountId, req.user.username], (err, rolls) => {
            if (err) return res.status(500).json({ message: 'DB error' });
            res.json({ stock_count_id: stockCountId, rolls });
        });
    });
});

app.post('/api/stock/check', authMiddleware, (req, res) => {
    const { stock_count_id, roll_number, found } = req.body;
    if (!stock_count_id || !roll_number) return res.status(400).json({ message: 'Missing fields' });
    db.get(`SELECT id FROM stock_check_items WHERE stock_count_id = ? AND roll_number = ? AND checked_by = ?`,
        [stock_count_id, roll_number, req.user.username], (err, row) => {
            if (err) return res.status(500).json({ message: 'DB error' });
            if (row) {
                db.run(`UPDATE stock_check_items SET found = ?, checked_at = CURRENT_TIMESTAMP WHERE id = ?`,
                    [found ? 1 : 0, row.id], (err) => {
                        if (err) return res.status(500).json({ message: 'Update failed' });
                        res.json({ ok: true });
                    });
            } else {
                db.run(`INSERT INTO stock_check_items (stock_count_id, roll_number, checked_by, found) VALUES (?, ?, ?, ?)`,
                    [stock_count_id, roll_number, req.user.username, found ? 1 : 0], (err) => {
                        if (err) return res.status(500).json({ message: 'Insert failed' });
                        res.json({ ok: true });
                    });
            }
        });
});

// ---------- Import Excel ----------
const upload = multer({ dest: 'uploads/' });

app.post('/api/import', authMiddleware, adminMiddleware, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const { count_number, stock_date, stock_time } = req.body;
    if (!count_number || !stock_date || !stock_time) {
        return res.status(400).json({ message: 'กรุณากรอกครั้งที่, วันที่ และเวลา' });
    }

    try {
        const workbook = xlsx.readFile(req.file.path);
        const sheet = workbook.Sheets[workbook.SheetNames[0]];
        const data = xlsx.utils.sheet_to_json(sheet, { defval: '' });

        let inserted = 0;
        const stmt = db.prepare(`INSERT OR REPLACE INTO rolls (
            roll_number, grade, width, supplier, supplier_grade, supplier_sn, dimeter, kgs, meter,
            supplier_doc_no, buy_date, ageing, qlt, customer, comp_no, loc, status, note, group_name
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

        db.serialize(() => {
            data.forEach(row => {
                const rollNumber = row['เบอร์ม้วน'] || row['roll_number'] || '';
                if (!rollNumber) return;
                
                // แปลงวันที่ buy_date ถ้าเป็นตัวเลข
                let buyDate = row['buy_date'] || '';
                if (buyDate && typeof buyDate === 'number') {
                    const epoch = new Date(1899, 11, 30);
                    const d = new Date(epoch.getTime() + buyDate * 86400000);
                    buyDate = d.toLocaleDateString('th-TH', { year: 'numeric', month: 'numeric', day: 'numeric' });
                } else if (buyDate && typeof buyDate === 'string') {
                    buyDate = buyDate.split('T')[0];
                }

                stmt.run(
                    rollNumber,
                    row['grade'] || '',
                    row['width'] ? String(row['width']) : '',
                    row['supplier'] || '',
                    row['supplier_grade'] || '',
                    row['supplier_sn'] || '',
                    row['dimeter'] ? String(row['dimeter']) : '',
                    row['kgs'] ? String(row['kgs']) : '',
                    row['meter'] ? String(row['meter']) : '',
                    row['supplier_doc_no'] || '',
                    buyDate,
                    row['ageing'] ? String(row['ageing']) : '',
                    row['qlt'] || '',
                    row['customer'] || '',
                    row['comp_no'] ? String(row['comp_no']) : '',
                    row['loc'] || '',
                    row['สถานะ'] || '',
                    row['note'] || '',
                    row['กลุ่ม'] || ''
                );
                inserted++;
            });
            stmt.finalize();

            db.run(`INSERT INTO stock_counts (count_number, stock_date, stock_time, created_by) VALUES (?, ?, ?, ?)`,
                [count_number, stock_date, stock_time, req.user.username]
            );

            db.run(`INSERT INTO import_history (filename, imported_by, rows_imported) VALUES (?, ?, ?)`,
                [req.file.originalname, req.user.username, inserted]
            );

            fs.unlinkSync(req.file.path);
            res.json({ ok: true, imported: inserted });
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'Import failed: ' + e.message });
    }
});

app.get('/api/import/history', authMiddleware, adminMiddleware, (req, res) => {
    db.all(`SELECT * FROM import_history ORDER BY import_date DESC`, (err, rows) => {
        if (err) return res.status(500).json({ message: 'DB error' });
        res.json({ history: rows });
    });
});

// ---------- Clear Data ----------
app.delete('/api/data/clear', authMiddleware, adminMiddleware, (req, res) => {
    db.run(`DELETE FROM rolls`, (err) => {
        if (err) return res.status(500).json({ message: 'Clear failed' });
        db.run(`DELETE FROM import_history`);
        db.run(`DELETE FROM stock_check_items`);
        res.json({ ok: true });
    });
});

app.delete('/api/data/clear-all', authMiddleware, adminMiddleware, (req, res) => {
    db.serialize(() => {
        db.run(`DELETE FROM rolls`);
        db.run(`DELETE FROM import_history`);
        db.run(`DELETE FROM stock_check_items`);
        db.run(`DELETE FROM stock_counts`);
        db.run(`DELETE FROM users WHERE role != 'admin'`);
        res.json({ ok: true });
    });
});

// ---------- Serve Frontend ----------
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/stock-check', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'stock-check.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
