require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const xlsx = require('xlsx');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

const app = express();
const PORT = process.env.PORT || 3000;

// ① SECRET_KEY จาก env (fallback: random เฉพาะ dev)
let SECRET_KEY = process.env.JWT_SECRET;
if (!SECRET_KEY || SECRET_KEY === 'your-secret-key-change-me') {
    if (process.env.NODE_ENV === 'production') {
        console.error('❌ JWT_SECRET ต้องถูกตั้งใน .env ก่อนรัน production');
        process.exit(1);
    }
    SECRET_KEY = crypto.randomBytes(32).toString('hex');
    console.warn('⚠️  ใช้ JWT_SECRET แบบสุ่มชั่วคราว (dev) — token จะหมดอายุเมื่อรีสตาร์ท');
}

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
        ? { rejectUnauthorized: false }
        : false
});

// ⑩ Rate limit สำหรับ login
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'พยายาม login หลายครั้งเกินไป กรุณารอสักครู่' }
});

// ---------- INIT DB ----------
const initDb = async () => {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, username TEXT UNIQUE, password TEXT,
            role TEXT DEFAULT 'user', is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

        await pool.query(`CREATE TABLE IF NOT EXISTS rolls (
            id SERIAL PRIMARY KEY, roll_number TEXT UNIQUE, grade TEXT, width TEXT,
            supplier TEXT, supplier_grade TEXT, supplier_sn TEXT, dimeter TEXT,
            kgs TEXT, meter TEXT, supplier_doc_no TEXT, buy_date TEXT, ageing TEXT,
            qlt TEXT, customer TEXT, comp_no TEXT, loc TEXT, status TEXT, note TEXT,
            group_name TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

        await pool.query(`CREATE TABLE IF NOT EXISTS import_history (
            id SERIAL PRIMARY KEY, filename TEXT, imported_by TEXT,
            rows_imported INTEGER, import_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

        await pool.query(`CREATE TABLE IF NOT EXISTS stock_counts (
            id SERIAL PRIMARY KEY, count_number TEXT, stock_date TEXT, stock_time TEXT,
            created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

        await pool.query(`CREATE TABLE IF NOT EXISTS stock_check_items (
            id SERIAL PRIMARY KEY, stock_count_id INTEGER, roll_number TEXT,
            checked_by TEXT, found INTEGER DEFAULT 0,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

        // ⑤ stock_alerts + stock_count_id
        await pool.query(`CREATE TABLE IF NOT EXISTS stock_alerts (
            id SERIAL PRIMARY KEY, roll_number TEXT, checked_by TEXT,
            stock_count_id INTEGER,
            alert_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved INTEGER DEFAULT 0)`);
        // migration: เผื่อตารางเก่าไม่มีคอลัมน์
        await pool.query(`ALTER TABLE stock_alerts ADD COLUMN IF NOT EXISTS stock_count_id INTEGER`);

        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_roll_number ON rolls(roll_number)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_group_name ON rolls(group_name)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_width ON rolls(width)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_rolls_status ON rolls(status)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_check_items_stock ON stock_check_items(stock_count_id, roll_number)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_check_items_user ON stock_check_items(stock_count_id, checked_by, roll_number)`);

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

// ---------- MIDDLEWARE ----------
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (e) {
        res.status(401).json({ message: 'Invalid token' });
    }
}
function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
    next();
}

// ⑦ escape LIKE wildcards (%, _, \)
function escapeLike(s) {
    return String(s).replace(/[\\%_]/g, c => '\\' + c);
}

// ④ helper: stock_count ล่าสุด
async function getLatestStockCountId() {
    const r = await pool.query(`SELECT id FROM stock_counts ORDER BY id DESC LIMIT 1`);
    return r.rows[0]?.id || null;
}

function convertExcelDate(value) {
    if (!value) return '';
    if (typeof value === 'number') {
        const epoch = new Date(1899, 11, 30);
        const d = new Date(epoch.getTime() + value * 86400000);
        return d.toLocaleDateString('th-TH', { year: 'numeric', month: 'numeric', day: 'numeric' });
    }
    if (typeof value === 'string') return value.split('T')[0].split(' ')[0];
    return String(value);
}

// ---------- AUTH ----------
app.post('/api/auth/login', authLimiter, async (req, res) => {
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
        await pool.query(`INSERT INTO users (username, password, role) VALUES ($1, $2, $3)`,
            [username, hashed, role || 'user']);
        res.json({ ok: true });
    } catch (e) {
        res.status(400).json({ message: 'Username already exists' });
    }
});

// ---------- USERS ----------
app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT id, username, role, is_active, created_at FROM users`);
        res.json({ users: result.rows });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

app.put('/api/users/:id/toggle', authMiddleware, adminMiddleware, async (req, res) => {
    const { is_active } = req.body;
    try {
        await pool.query(`UPDATE users SET is_active = $1 WHERE id = $2`, [is_active ? 1 : 0, req.params.id]);
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ message: 'Update failed' }); }
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`DELETE FROM users WHERE id = $1 AND role != 'admin'`, [req.params.id]);
        if (result.rowCount === 0) return res.status(400).json({ message: 'Cannot delete admin or user not found' });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

// ---------- ROLLS ----------
app.get('/api/rolls/search', authMiddleware, async (req, res) => {
    const q = req.query.q || '';
    try {
        const result = await pool.query(`SELECT * FROM rolls WHERE roll_number = $1`, [q]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Not found' });
        const roll = result.rows[0];
        if (roll.buy_date) roll.buy_date = convertExcelDate(roll.buy_date);
        res.json({ roll });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

app.get('/api/rolls/suggest', authMiddleware, async (req, res) => {
    const q = req.query.q || '';
    if (q.length < 1) return res.json([]);
    try {
        const result = await pool.query(
            `SELECT roll_number FROM rolls WHERE roll_number LIKE $1 ESCAPE '\\' LIMIT 20`,
            ['%' + escapeLike(q) + '%']
        );
        res.json(result.rows.map(r => r.roll_number));
    } catch (e) { res.status(500).json([]); }
});

app.get('/api/rolls/count', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT COUNT(*) as count FROM rolls`);
        res.json({ count: parseInt(result.rows[0].count) });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
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
            by_status: {
                'เต็ม': parseInt(full.rows[0].count),
                'เศษ': parseInt(scrap.rows[0].count),
                'รอกรอ': parseInt(wait.rows[0].count)
            }
        });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

// ---------- ⭐ NEW: DASHBOARD GROUP SUMMARY ----------
app.get('/api/dashboard/group-summary', authMiddleware, async (req, res) => {
    try {
        const stockId = await getLatestStockCountId();

        const totalResult = await pool.query(`SELECT COUNT(*)::int AS total FROM rolls`);
        let foundTotal = 0;
        if (stockId) {
            const fr = await pool.query(
                `SELECT COUNT(DISTINCT roll_number)::int AS found
                 FROM stock_check_items
                 WHERE stock_count_id = $1 AND found = 1`,
                [stockId]
            );
            foundTotal = fr.rows[0].found || 0;
        }
        const total = totalResult.rows[0].total;
        foundTotal = Math.min(foundTotal, total);
        const notFoundTotal = total - foundTotal;

        const q = `
            SELECT r.group_name, r.width,
                   COUNT(*)::int AS total,
                   COUNT(*) FILTER (WHERE EXISTS (
                       SELECT 1 FROM stock_check_items sci
                       WHERE sci.stock_count_id = $1
                         AND sci.roll_number = r.roll_number
                         AND sci.found = 1
                   ))::int AS found
            FROM rolls r
            GROUP BY r.group_name, r.width
            ORDER BY r.group_name NULLS LAST,
                     CASE WHEN r.width ~ '^[0-9]+$' THEN CAST(r.width AS INTEGER) ELSE 99999 END,
                     r.width
        `;
        const rows = (await pool.query(q, [stockId])).rows;

        const groupMap = new Map();
        for (const row of rows) {
            const gname = row.group_name || '(ไม่มีกลุ่ม)';
            if (!groupMap.has(gname)) {
                groupMap.set(gname, { group_name: gname, total: 0, found: 0, sizes: [] });
            }
            const g = groupMap.get(gname);
            g.total += row.total;
            g.found += row.found;
            g.sizes.push({
                width: row.width || '—',
                total: row.total,
                found: row.found,
                not_found: row.total - row.found
            });
        }

        const groups = Array.from(groupMap.values()).map(g => {
            g.not_found = g.total - g.found;
            g.percent_found = g.total > 0 ? (g.found / g.total * 100) : 0;
            g.sizes = g.sizes.map(s => ({
                ...s,
                percent_found: s.total > 0 ? (s.found / s.total * 100) : 0
            }));
            return g;
        });

        res.json({
            groups,
            overall: {
                total,
                found: foundTotal,
                not_found: notFoundTotal,
                percent_found: total > 0 ? (foundTotal / total * 100) : 0
            }
        });
    } catch (e) {
        console.error('group-summary error:', e);
        res.status(500).json({ message: 'DB error: ' + e.message });
    }
});

// ---------- ⭐ NEW: DASHBOARD NOT FOUND LIST ----------
app.get('/api/dashboard/not-found-list', authMiddleware, async (req, res) => {
    try {
        const stockId = await getLatestStockCountId();
        const where = `NOT EXISTS (
            SELECT 1 FROM stock_check_items sci
            WHERE sci.stock_count_id = $1
              AND sci.roll_number = r.roll_number
              AND sci.found = 1
        )`;
        const q = `
            SELECT r.roll_number, r.width, r.group_name, r.loc, r.status, r.grade, r.dimeter, r.kgs
            FROM rolls r
            WHERE ${where}
            ORDER BY r.group_name NULLS LAST, r.width, r.roll_number
            LIMIT 5000
        `;
        const result = await pool.query(q, [stockId]);
        res.json({ rolls: result.rows, stock_id: stockId });
    } catch (e) {
        console.error('not-found-list error:', e);
        res.status(500).json({ message: 'DB error: ' + e.message });
    }
});

// ---------- STOCK SETTINGS ----------
app.post('/api/stock/settings', authMiddleware, adminMiddleware, async (req, res) => {
    const { count_number, stock_date, stock_time } = req.body;
    if (!count_number || !stock_date || !stock_time) {
        return res.status(400).json({ message: 'Missing fields' });
    }
    try {
        const existing = await pool.query(`SELECT id FROM stock_counts WHERE count_number = $1`, [count_number]);
        if (existing.rows.length > 0) {
            await pool.query(
                `UPDATE stock_counts SET stock_date = $1, stock_time = $2, created_by = $3 WHERE id = $4`,
                [stock_date, stock_time, req.user.username, existing.rows[0].id]
            );
        } else {
            await pool.query(
                `INSERT INTO stock_counts (count_number, stock_date, stock_time, created_by) VALUES ($1,$2,$3,$4)`,
                [count_number, stock_date, stock_time, req.user.username]
            );
        }
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ message: 'Failed to save settings' }); }
});

app.get('/api/stock/latest', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM stock_counts ORDER BY id DESC LIMIT 1`);
        if (result.rows.length === 0) return res.status(404).json({ message: 'No settings found' });
        res.json(result.rows[0]);
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

app.get('/api/stock/groups', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT DISTINCT group_name FROM rolls WHERE group_name IS NOT NULL AND group_name != '' ORDER BY group_name`
        );
        res.json({ groups: result.rows.map(r => r.group_name) });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

// ---------- ⑧ check-sizes (โหลดขนาดก่อน) ----------
app.get('/api/stock/check-sizes', authMiddleware, async (req, res) => {
    const group = req.query.group || 'all';
    const status = req.query.status || 'all';

    const params = [];
    let where = '1=1';
    if (group !== 'all') { params.push(group); where += ` AND r.group_name = $${params.length}`; }
    if (status !== 'all') { params.push(status); where += ` AND r.status = $${params.length}`; }

    try {
        const stockId = await getLatestStockCountId();
        params.push(stockId);
        const stockIdIdx = params.length;

        const q = `
            SELECT r.width,
                   COUNT(*)::int AS total,
                   COUNT(*) FILTER (WHERE EXISTS (
                       SELECT 1 FROM stock_check_items sci
                       WHERE sci.stock_count_id = $${stockIdIdx}
                         AND sci.roll_number = r.roll_number
                         AND sci.found = 1
                   ))::int AS found
            FROM rolls r
            WHERE ${where}
            GROUP BY r.width
            ORDER BY CASE WHEN r.width ~ '^[0-9]+$' THEN CAST(r.width AS INTEGER) ELSE 99999 END, r.width
        `;
        const result = await pool.query(q, params);
        res.json({ sizes: result.rows });
    } catch (e) {
        console.error('check-sizes error:', e);
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- ③ ④ ⑧ check-items ----------
app.get('/api/stock/check-items', authMiddleware, async (req, res) => {
    const group = req.query.group || 'all';
    const status = req.query.status || 'all';
    const size = req.query.size;
    if (!size) return res.status(400).json({ message: 'size is required' });

    const username = req.user.username;
    const params = [username, String(size)];
    let where = 'r.width = $2';
    if (group !== 'all') { params.push(group); where += ` AND r.group_name = $${params.length}`; }
    if (status !== 'all') { params.push(status); where += ` AND r.status = $${params.length}`; }

    try {
        const stockId = await getLatestStockCountId();
        params.push(stockId);
        const stockIdIdx = params.length;

        const q = `
            SELECT r.*,
                   COALESCE(my.found, 0) AS found_by_me,
                   agg.checked_by_list AS checked_by,
                   (agg.checked_by_list IS NOT NULL) AS found_any
            FROM rolls r
            LEFT JOIN (
                SELECT roll_number, MAX(found) AS found
                FROM stock_check_items
                WHERE stock_count_id = $${stockIdIdx} AND checked_by = $1
                GROUP BY roll_number
            ) my ON my.roll_number = r.roll_number
            LEFT JOIN (
                SELECT roll_number, STRING_AGG(DISTINCT checked_by, ', ') AS checked_by_list
                FROM stock_check_items
                WHERE stock_count_id = $${stockIdIdx} AND found = 1
                GROUP BY roll_number
            ) agg ON agg.roll_number = r.roll_number
            WHERE ${where}
            ORDER BY r.loc ASC NULLS LAST,
                     CASE r.status WHEN 'เต็ม' THEN 0 WHEN 'เศษ' THEN 1 WHEN 'รอกรอ' THEN 2 ELSE 3 END,
                     r.grade ASC
            LIMIT 2000
        `;
        const result = await pool.query(q, params);
        res.json({ rolls: result.rows });
    } catch (e) {
        console.error('check-items error:', e);
        res.status(500).json({ message: 'DB error: ' + e.message });
    }
});

// ---------- STOCK CHECK (บันทึก) ----------
app.post('/api/stock/check', authMiddleware, async (req, res) => {
    const { roll_number, found, checked_by } = req.body;
    if (!roll_number) return res.status(400).json({ message: 'Missing roll number' });
    const checker = checked_by || req.user.username;

    try {
        const stockId = await getLatestStockCountId();
        if (!stockId) return res.status(400).json({ message: 'No stock count settings' });

        const rollCheck = await pool.query(`SELECT roll_number FROM rolls WHERE roll_number = $1`, [roll_number]);
        if (rollCheck.rows.length === 0 && found === 1) {
            await pool.query(
                `INSERT INTO stock_alerts (roll_number, checked_by, stock_count_id) VALUES ($1, $2, $3)`,
                [roll_number, checker, stockId]
            );
        }

        const checkResult = await pool.query(
            `SELECT id FROM stock_check_items WHERE stock_count_id = $1 AND roll_number = $2 AND checked_by = $3`,
            [stockId, roll_number, checker]
        );
        if (checkResult.rows.length > 0) {
            await pool.query(
                `UPDATE stock_check_items SET found = $1, checked_at = CURRENT_TIMESTAMP WHERE id = $2`,
                [found ? 1 : 0, checkResult.rows[0].id]
            );
        } else {
            await pool.query(
                `INSERT INTO stock_check_items (stock_count_id, roll_number, checked_by, found) VALUES ($1, $2, $3, $4)`,
                [stockId, roll_number, checker, found ? 1 : 0]
            );
        }
        res.json({ ok: true });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'DB error' });
    }
});

// ---------- ALERTS ----------
app.get('/api/alerts', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM stock_alerts WHERE resolved = 0 ORDER BY alert_date DESC`);
        res.json({ alerts: result.rows });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

app.put('/api/alerts/:id/resolve', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await pool.query(`UPDATE stock_alerts SET resolved = 1 WHERE id = $1`, [req.params.id]);
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ message: 'Update failed' }); }
});

// ---------- IMPORT EXCEL ----------
// ⑩ จำกัดขนาดไฟล์ 20 MB
const upload = multer({
    dest: 'uploads/',
    limits: { fileSize: 20 * 1024 * 1024 }
});

app.post('/api/import', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const { count_number, stock_date, stock_time } = req.body;
    if (!count_number || !stock_date || !stock_time) {
        try { fs.unlinkSync(req.file.path); } catch (e) {}
        return res.status(400).json({ message: 'กรุณากรอกครั้งที่, วันที่ และเวลา' });
    }

    const client = await pool.connect();
    let inserted = 0;
    try {
        await client.query('BEGIN');

        const workbook = xlsx.readFile(req.file.path);
        const sheet = workbook.Sheets[workbook.SheetNames[0]];
        const data = xlsx.utils.sheet_to_json(sheet, { defval: '' });

        // ⭐ แปลงข้อมูลทั้งหมดก่อน (ใน memory)
        const rows = [];
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
            rows.push([
                String(rollNumber).trim(),
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
        }

        // ⭐ Deduplicate: เก็บแถวสุดท้ายของแต่ละ roll_number (แก้ error "cannot affect row a second time")
        const dedupMap = new Map();
        for (const r of rows) {
            dedupMap.set(r[0], r);  // r[0] = roll_number
        }
        const uniqueRows = Array.from(dedupMap.values());

        // ⭐ BATCH INSERT — ทีละ 500 แถว
        const BATCH_SIZE = 500;
        const COLS = 19;
        for (let i = 0; i < uniqueRows.length; i += BATCH_SIZE) {
            const batch = uniqueRows.slice(i, i + BATCH_SIZE);

            const values = [];
            const placeholders = batch.map((rowVals, rowIdx) => {
                const base = rowIdx * COLS;
                const ph = Array.from({ length: COLS }, (_, k) => '$' + (base + k + 1));
                values.push(...rowVals);
                return '(' + ph.join(',') + ')';
            }).join(',');

            await client.query(`
                INSERT INTO rolls (
                    roll_number, grade, width, supplier, supplier_grade, supplier_sn, dimeter, kgs, meter,
                    supplier_doc_no, buy_date, ageing, qlt, customer, comp_no, loc, status, note, group_name
                ) VALUES ${placeholders}
                ON CONFLICT (roll_number) DO UPDATE SET
                    grade=EXCLUDED.grade, width=EXCLUDED.width, supplier=EXCLUDED.supplier,
                    supplier_grade=EXCLUDED.supplier_grade, supplier_sn=EXCLUDED.supplier_sn,
                    dimeter=EXCLUDED.dimeter, kgs=EXCLUDED.kgs, meter=EXCLUDED.meter,
                    supplier_doc_no=EXCLUDED.supplier_doc_no, buy_date=EXCLUDED.buy_date,
                    ageing=EXCLUDED.ageing, qlt=EXCLUDED.qlt, customer=EXCLUDED.customer,
                    comp_no=EXCLUDED.comp_no, loc=EXCLUDED.loc, status=EXCLUDED.status,
                    note=EXCLUDED.note, group_name=EXCLUDED.group_name
            `, values);
            inserted += batch.length;
        }

        // upsert stock_counts
        const existing = await client.query(`SELECT id FROM stock_counts WHERE count_number = $1`, [count_number]);
        if (existing.rows.length > 0) {
            await client.query(
                `UPDATE stock_counts SET stock_date = $1, stock_time = $2, created_by = $3 WHERE id = $4`,
                [stock_date, stock_time, req.user.username, existing.rows[0].id]
            );
        } else {
            await client.query(
                `INSERT INTO stock_counts (count_number, stock_date, stock_time, created_by) VALUES ($1,$2,$3,$4)`,
                [count_number, stock_date, stock_time, req.user.username]
            );
        }

        await client.query(
            `INSERT INTO import_history (filename, imported_by, rows_imported) VALUES ($1, $2, $3)`,
            [req.file.originalname, req.user.username, inserted]
        );

        await client.query('COMMIT');
        res.json({ ok: true, imported: inserted });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error(e);
        res.status(500).json({ message: 'Import failed: ' + e.message });
    } finally {
        client.release();
        try { fs.unlinkSync(req.file.path); } catch (e) {}
    }
});

app.get('/api/import/history', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM import_history ORDER BY import_date DESC`);
        res.json({ history: result.rows });
    } catch (e) { res.status(500).json({ message: 'DB error' }); }
});

// ---------- CLEAR DATA ----------
app.delete('/api/data/clear', authMiddleware, adminMiddleware, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`DELETE FROM rolls`);
        await client.query(`DELETE FROM import_history`);
        await client.query(`DELETE FROM stock_check_items`);
        await client.query(`DELETE FROM stock_alerts`);
        await client.query('COMMIT');
        res.json({ ok: true });
    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ message: 'Clear failed' });
    } finally { client.release(); }
});

app.delete('/api/data/clear-all', authMiddleware, adminMiddleware, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`DELETE FROM rolls`);
        await client.query(`DELETE FROM import_history`);
        await client.query(`DELETE FROM stock_check_items`);
        await client.query(`DELETE FROM stock_alerts`);
        await client.query(`DELETE FROM stock_counts`);
        await client.query(`DELETE FROM users WHERE role != 'admin'`);
        await client.query('COMMIT');
        res.json({ ok: true });
    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ message: 'Clear failed' });
    } finally { client.release(); }
});

// ---------- SERVE FRONTEND ----------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/stock-check', (req, res) => res.sendFile(path.join(__dirname, 'public', 'stock-check.html')));
app.get('/label', (req, res) => res.sendFile(path.join(__dirname, 'public', 'label.html')));

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT} (PostgreSQL Ready)`);
});
