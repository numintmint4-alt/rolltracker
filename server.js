const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const xlsx = require('xlsx');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your-secret-key-change-me';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ---------- PostgreSQL Connection ----------
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ---------- Initialize Database Tables ----------
const initDb = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS rolls (
                id SERIAL PRIMARY KEY,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS import_history (
                id SERIAL PRIMARY KEY,
                filename TEXT,
                imported_by TEXT,
                rows_imported INTEGER,
                import_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS stock_counts (
                id SERIAL PRIMARY KEY,
                count_number TEXT,
                stock_date TEXT,
                stock_time TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS stock_check_items (
                id SERIAL PRIMARY KEY,
                stock_count_id INTEGER,
                roll_number TEXT,
                checked_by TEXT,
                found INTEGER DEFAULT 0,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS stock_alerts (
                id SERIAL PRIMARY KEY,
                roll_number TEXT,
                checked_by TEXT,
                alert_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved INTEGER DEFAULT 0
            )
        `);

        // Create indexes
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_roll_number ON rolls(roll_number)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_group_name ON rolls(group_name)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_width ON rolls(width)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_status ON rolls(status)`);

        // Create default admin & user
        const adminPass = bcrypt.hashSync('admin123', 10);
        const userPass = bcrypt.hashSync('user123', 10);

        const adminCheck = await pool.query(`SELECT id FROM users WHERE username = 'admin'`);
        if (adminCheck.rows.length === 0) {
            await pool.query(`INSERT INTO users (username, password, role) VALUES ($1, $2, 'admin')`, ['admin', adminPass]);
            console.log('✅ Created default admin: admin / admin123');
        }
        const userCheck = await pool.query(`SELECT id FROM users WHERE username = 'user'`);
        if (userCheck.rows.length === 0) {
            await pool.query(`INSERT INTO users (username, password, role) VALUES ($1, $2, 'user')`, ['user', userPass]);
            console.log('✅ Created default user: user / user123');
        }
        console.log('✅ Database initialized successfully');
    } catch (err) {
        console.error('Database init error:', err);
    }
};

initDb();

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

function convertExcelDate(value) {
    if (!value) return '';
    if (typeof value === 'number') {
        const epoch = new Date(1899, 11, 30);
        const d = new Date(epoch.getTime() + value * 86400000);
        return d.toLocaleDateString('th-TH', { year: 'numeric', month: 'numeric', day: 'numeric' });
    }
    if (typeof value === 'string') {
        const parts = value.split('T');
        return parts[0].split(' ')[0];
    }
    return String(value);
}

// ---------- Auth Routes ----------
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Missing credentials' });
    try {
        const result = await pool.query(`SELECT * FROM users WHERE username = $1 AND is_active = 1`, [username]);
        const user = result.rows[0];
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1d' });
        res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT id, username, role FROM users WHERE id = $1`, [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'User not found' });
        res.json({ user: result.rows[0] });
    } catch (e) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/register', authMiddleware, adminMiddleware, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Missing fields' });
    const hashed = bcrypt.hashSync(password, 10);
    try {
        await pool.query(`INSERT INTO users (username, password, role) VALUES ($1, $2, $3)`, [username, hashed, role || 'user']);
        res.json({ ok: true });
    } catch (e) {
        res.status(400).json({ message: 'Username already exists' });
    }
});

// ---------- User Management ----------
app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT id, username, role, is_active, created_at FROM users`);
        res.json({ users: result.rows });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

app.put('/api/users/:id/toggle', authMiddleware, adminMiddleware, async (req, res) => {
    const { is_active } = req.body;
    try {
        await pool.query(`UPDATE users SET is_active = $1 WHERE id = $2`, [is_active ? 1 : 0, req.params.id]);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ message: 'Update failed' });
    }
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`DELETE FROM users WHERE id = $1 AND role != 'admin'`, [req.params.id]);
        if (result.rowCount === 0) return res.status(400).json({ message: 'Cannot delete admin or user not found' });
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- Rolls ----------
app.get('/api/rolls/search', authMiddleware, async (req, res) => {
    const q = req.query.q || '';
    try {
        const result = await pool.query(`SELECT * FROM rolls WHERE roll_number = $1`, [q]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Not found' });
        const roll = result.rows[0];
        if (roll.buy_date) roll.buy_date = convertExcelDate(roll.buy_date);
        res.json({ roll });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

app.get('/api/rolls/suggest', authMiddleware, async (req, res) => {
    const q = req.query.q || '';
    if (q.length < 1) return res.json([]);
    try {
        const result = await pool.query(`SELECT roll_number FROM rolls WHERE roll_number LIKE $1 LIMIT 20`, [`%${q.replace(/%/g,'\\%')}%`]);
        res.json(result.rows.map(r => r.roll_number));
    } catch (e) {
        res.status(500).json([]);
    }
});

app.get('/api/rolls/count', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT COUNT(*) as count FROM rolls`);
        res.json({ count: parseInt(result.rows[0].count) });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
    try {
        const total = await pool.query(`SELECT COUNT(*) as count FROM rolls`);
        const loc1 = await pool.query(`SELECT COUNT(*) as count FROM rolls WHERE loc = 'LOC1'`);
        const locf = await pool.query(`SELECT COUNT(*) as count FROM rolls WHERE loc = 'LOCF'`);
        const full = await pool.query(`SELECT COUNT(*) as count FROM rolls WHERE status = 'เต็ม'`);
        const scrap = await pool.query(`SELECT COUNT(*) as count FROM rolls WHERE status = 'เศษ'`);
        const wait = await pool.query(`SELECT COUNT(*) as count FROM rolls WHERE status = 'รอกรอ'`);

        res.json({
            total: parseInt(total.rows[0].count),
            by_loc: { LOC1: parseInt(loc1.rows[0].count), LOCF: parseInt(locf.rows[0].count) },
            by_status: { 'เต็ม': parseInt(full.rows[0].count), 'เศษ': parseInt(scrap.rows[0].count), 'รอกรอ': parseInt(wait.rows[0].count) }
        });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- Stock Settings ----------
app.post('/api/stock/settings', authMiddleware, adminMiddleware, async (req, res) => {
    const { count_number, stock_date, stock_time } = req.body;
    if (!count_number || !stock_date || !stock_time) {
        return res.status(400).json({ message: 'Missing fields' });
    }
    try {
        await pool.query(`INSERT INTO stock_counts (count_number, stock_date, stock_time, created_by) VALUES ($1, $2, $3, $4)`,
            [count_number, stock_date, stock_time, req.user.username]);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ message: 'Failed to save settings' });
    }
});

app.get('/api/stock/latest', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM stock_counts ORDER BY id DESC LIMIT 1`);
        if (result.rows.length === 0) return res.status(404).json({ message: 'No settings found' });
        res.json(result.rows[0]);
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- Get all groups ----------
app.get('/api/stock/groups', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT DISTINCT group_name FROM rolls WHERE group_name IS NOT NULL AND group_name != '' ORDER BY group_name`);
        res.json({ groups: result.rows.map(r => r.group_name) });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- Stock Check ----------
app.get('/api/stock/check-items', authMiddleware, async (req, res) => {
    const group = req.query.group || 'all';
    const status = req.query.status || 'all';
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    let whereClause = '1=1';
    const params = [];
    let paramCount = 1;

    if (group !== 'all') {
        whereClause += ` AND group_name = $${paramCount}`;
        params.push(group);
        paramCount++;
    }
    if (status !== 'all') {
        whereClause += ` AND status = $${paramCount}`;
        params.push(status);
        paramCount++;
    }

    try {
        const countResult = await pool.query(`SELECT COUNT(*) as total FROM rolls WHERE ${whereClause}`, params);
        const total = parseInt(countResult.rows[0].total);

        const queryParams = [req.user.username, ...params];
        let query = `
            SELECT r.*,
                   (SELECT found FROM stock_check_items WHERE stock_count_id = (SELECT id FROM stock_counts ORDER BY id DESC LIMIT 1) AND roll_number = r.roll_number AND checked_by = $1) as found,
                   (SELECT checked_by FROM stock_check_items WHERE stock_count_id = (SELECT id FROM stock_counts ORDER BY id DESC LIMIT 1) AND roll_number = r.roll_number AND found = 1) as checked_by
            FROM rolls r
            WHERE ${whereClause}
            ORDER BY r.loc ASC, 
                     CASE r.status WHEN 'เต็ม' THEN 0 WHEN 'เศษ' THEN 1 WHEN 'รอกรอ' THEN 2 ELSE 3 END,
                     CAST(r.width AS INTEGER) ASC,
                     r.grade ASC
            LIMIT $${params.length + 2} OFFSET $${params.length + 3}
        `;
        const dataParams = [...queryParams, limit, offset];
        const result = await pool.query(query, dataParams);

        res.json({
            stock_count_id: null,
            rolls: result.rows,
            total,
            page,
            totalPages: Math.ceil(total / limit),
            limit
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'DB error' });
    }
});

app.post('/api/stock/check', authMiddleware, async (req, res) => {
    const { roll_number, found, checked_by } = req.body;
    if (!roll_number) return res.status(400).json({ message: 'Missing roll number' });
    
    const checker = checked_by || req.user.username;

    try {
        const stockResult = await pool.query(`SELECT id FROM stock_counts ORDER BY id DESC LIMIT 1`);
        if (stockResult.rows.length === 0) {
            return res.status(400).json({ message: 'No stock count settings' });
        }
        const stockCountId = stockResult.rows[0].id;

        const rollCheck = await pool.query(`SELECT roll_number FROM rolls WHERE roll_number = $1`, [roll_number]);
        if (rollCheck.rows.length === 0 && found === 1) {
            await pool.query(`INSERT INTO stock_alerts (roll_number, checked_by) VALUES ($1, $2)`, [roll_number, checker]);
        }

        const checkResult = await pool.query(`SELECT id FROM stock_check_items WHERE stock_count_id = $1 AND roll_number = $2 AND checked_by = $3`,
            [stockCountId, roll_number, checker]);
        if (checkResult.rows.length > 0) {
            await pool.query(`UPDATE stock_check_items SET found = $1, checked_at = CURRENT_TIMESTAMP WHERE id = $2`,
                [found ? 1 : 0, checkResult.rows[0].id]);
        } else {
            await pool.query(`INSERT INTO stock_check_items (stock_count_id, roll_number, checked_by, found) VALUES ($1, $2, $3, $4)`,
                [stockCountId, roll_number, checker, found ? 1 : 0]);
        }
        res.json({ ok: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- Admin Alerts ----------
app.get('/api/alerts', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM stock_alerts WHERE resolved = 0 ORDER BY alert_date DESC`);
        res.json({ alerts: result.rows });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

app.put('/api/alerts/:id/resolve', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await pool.query(`UPDATE stock_alerts SET resolved = 1 WHERE id = $1`, [req.params.id]);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ message: 'Update failed' });
    }
});

// ---------- Import Excel ----------
const upload = multer({ dest: 'uploads/' });

app.post('/api/import', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
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
        for (const row of data) {
            const rollNumber = row['เบอร์ม้วน'] || row['roll_number'] || '';
            if (!rollNumber) continue;
            let buyDate = row['buy_date'] || '';
            if (buyDate && typeof buyDate === 'number') {
                const epoch = new Date(1899, 11, 30);
                const d = new Date(epoch.getTime() + buyDate * 86400000);
                buyDate = d.toLocaleDateString('th-TH', { year: 'numeric', month: 'numeric', day: 'numeric' });
            } else if (buyDate && typeof buyDate === 'string') {
                buyDate = buyDate.split('T')[0];
            }
            await pool.query(`
                INSERT INTO rolls (
                    roll_number, grade, width, supplier, supplier_grade, supplier_sn, dimeter, kgs, meter,
                    supplier_doc_no, buy_date, ageing, qlt, customer, comp_no, loc, status, note, group_name
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
                ON CONFLICT (roll_number) DO UPDATE SET
                    grade=EXCLUDED.grade, width=EXCLUDED.width, supplier=EXCLUDED.supplier,
                    supplier_grade=EXCLUDED.supplier_grade, supplier_sn=EXCLUDED.supplier_sn,
                    dimeter=EXCLUDED.dimeter, kgs=EXCLUDED.kgs, meter=EXCLUDED.meter,
                    supplier_doc_no=EXCLUDED.supplier_doc_no, buy_date=EXCLUDED.buy_date,
                    ageing=EXCLUDED.ageing, qlt=EXCLUDED.qlt, customer=EXCLUDED.customer,
                    comp_no=EXCLUDED.comp_no, loc=EXCLUDED.loc, status=EXCLUDED.status,
                    note=EXCLUDED.note, group_name=EXCLUDED.group_name
            `, [
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
            ]);
            inserted++;
        }

        await pool.query(`INSERT INTO stock_counts (count_number, stock_date, stock_time, created_by) VALUES ($1, $2, $3, $4)`,
            [count_number, stock_date, stock_time, req.user.username]);
        await pool.query(`INSERT INTO import_history (filename, imported_by, rows_imported) VALUES ($1, $2, $3)`,
            [req.file.originalname, req.user.username, inserted]);

        fs.unlinkSync(req.file.path);
        res.json({ ok: true, imported: inserted });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'Import failed: ' + e.message });
    }
});

app.get('/api/import/history', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM import_history ORDER BY import_date DESC`);
        res.json({ history: result.rows });
    } catch (e) {
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- Clear Data ----------
app.delete('/api/data/clear', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await pool.query(`DELETE FROM rolls`);
        await pool.query(`DELETE FROM import_history`);
        await pool.query(`DELETE FROM stock_check_items`);
        await pool.query(`DELETE FROM stock_alerts`);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ message: 'Clear failed' });
    }
});

app.delete('/api/data/clear-all', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await pool.query(`DELETE FROM rolls`);
        await pool.query(`DELETE FROM import_history`);
        await pool.query(`DELETE FROM stock_check_items`);
        await pool.query(`DELETE FROM stock_alerts`);
        await pool.query(`DELETE FROM stock_counts`);
        await pool.query(`DELETE FROM users WHERE role != 'admin'`);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ message: 'Clear failed' });
    }
});

// ---------- Serve Frontend ----------
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/stock-check', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'stock-check.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT} (PostgreSQL Ready)`);
});