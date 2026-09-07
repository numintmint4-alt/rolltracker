const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const xlsx = require('xlsx');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your-secret-key-change-me';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database
const db = new sqlite3.Database('./rolls.db', (err) => {
    if (err) console.error('Database error:', err.message);
    else console.log('Connected to SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
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
    db.run(`CREATE TABLE IF NOT EXISTS import_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        imported_by TEXT,
        rows_imported INTEGER,
        import_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

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

app.get('/api/rolls/search', authMiddleware, (req, res) => {
    const q = req.query.q || '';
    db.get(`SELECT * FROM rolls WHERE roll_number = ?`, [q], (err, roll) => {
        if (err) return res.status(500).json({ message: 'DB error' });
        if (!roll) return res.status(404).json({ message: 'Not found' });
        res.json({ roll });
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

const upload = multer({ dest: 'uploads/' });
app.post('/api/import', authMiddleware, adminMiddleware, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
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
                    row['buy_date'] ? String(row['buy_date']) : '',
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

app.delete('/api/data/clear', authMiddleware, adminMiddleware, (req, res) => {
    db.run(`DELETE FROM rolls`, (err) => {
        if (err) return res.status(500).json({ message: 'Clear failed' });
        db.run(`DELETE FROM import_history`);
        res.json({ ok: true });
    });
});

app.delete('/api/data/clear-all', authMiddleware, adminMiddleware, (req, res) => {
    db.serialize(() => {
        db.run(`DELETE FROM rolls`);
        db.run(`DELETE FROM import_history`);
        db.run(`DELETE FROM users WHERE role != 'admin'`);
        res.json({ ok: true });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});