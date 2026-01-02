const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { query } = require('./db');
const { signToken, authMiddleware, requireRole, getUserByEmail, getUserById } = require('./auth');
const { notifyRole, notifyUsers } = require('./notify');
const { logAudit } = require('./audit');
const { createBackup, listBackups, restoreFromSql } = require('./backup');
const ExcelJS = require('exceljs');
const crypto = require('crypto');

function slNowColombo() {
  const now = new Date();
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Colombo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  }).formatToParts(now);
  const get = t => fmt.find(p=>p.type===t)?.value;
  return {
    date: `${get('year')}-${get('month')}-${get('day')}`,
    time: `${get('hour')}:${get('minute')}`
  };
}

async function generateLeaveCode(){
  // 6-digit random code (000000 - 999999) used as the leave identification code for security OUT/IN
  // Retry a few times to avoid collisions.
  for(let attempt=0; attempt<15; attempt++){
    const code = String(crypto.randomInt(0, 1000000)).padStart(6,'0');
    const { rows } = await query('SELECT 1 FROM leaves WHERE leave_code=$1 LIMIT 1', [code]);
    if(!rows.length) return code;
  }
  throw new Error('Failed to generate unique leave code');
}



function statusTarget(status){
  const s = String(status||'').toUpperCase();
  if(s === 'PENDING_HOD') return { role:'HOD', departmentScoped:true };
  if(s === 'PENDING_ADMIN') return { role:'ADMIN', departmentScoped:false };
  if(s === 'PENDING_HR') return { role:'HR', departmentScoped:false };
  return null;
}

async function notifyByStatus(status, department_id, payload){
  const t = statusTarget(status);
  if(!t) return 0;
  if(t.departmentScoped) return notifyRole(t.role, payload, department_id);
  return notifyRole(t.role, payload);
}
// Simple helper
function minutesBetween(out, inn) {
  if (!out || !inn) return null;
  const [oh,om] = out.split(':').map(Number);
  const [ih,im] = inn.split(':').map(Number);
  return (ih*60+im)-(oh*60+om);
}

// --------
// Validation helpers (reports/filters)
// --------
function parseIntParam(v, def=null){
  if (v === undefined || v === null || v === '') return def;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : def;
}

function parseBoolParam(v){
  if (v === undefined || v === null || v === '') return null;
  const s = String(v).toLowerCase();
  if (s === '1' || s === 'true' || s === 'yes') return true;
  if (s === '0' || s === 'false' || s === 'no') return false;
  return null;
}

function isISODate(s){
  return /^\d{4}-\d{2}-\d{2}$/.test(String(s||''));
}

function parseStatusList(v){
  if (v === undefined || v === null || v === '') return null;
  const raw = Array.isArray(v) ? v.join(',') : String(v);
  const list = raw.split(',').map(x=>x.trim()).filter(Boolean);
  if (!list.length) return null;
  return list.map(x=>x.toUpperCase());
}

function toCSV(rows, columns){
  const esc = (val)=>{
    if (val === null || val === undefined) return '';
    const s = String(val);
    const needs = /[\n\r,\"]/g.test(s);
    const out = s.replace(/\"/g, '""');
    return needs ? `"${out}"` : out;
  };
  const head = columns.map(c=>esc(c.header)).join(',');
  const body = rows.map(r => columns.map(c=>esc(c.get(r))).join(',')).join('\n');
  // UTF-8 BOM for Excel Sinhala compatibility
  return '\ufeff' + head + '\n' + body + '\n';
}

async function ensureSchema() {
  // departments
  await query('CREATE TABLE IF NOT EXISTS departments(id SERIAL PRIMARY KEY,name TEXT NOT NULL UNIQUE);');

  // users (add created_at because later endpoints query it)
  await query(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    emp_no TEXT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    department_id INTEGER REFERENCES departments(id),
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );`);

  // leaves (match all columns used in queries)
  await query(`CREATE TABLE IF NOT EXISTS leaves(
    id SERIAL PRIMARY KEY,
    leave_code TEXT UNIQUE,
    employee_id INTEGER REFERENCES users(id),
    is_hod_request BOOLEAN NOT NULL DEFAULT FALSE,
    is_unregistered BOOLEAN NOT NULL DEFAULT FALSE,

    -- New column names used by code
    unregistered_emp_id TEXT,
    unregistered_name TEXT,
    unregistered_department TEXT,

    -- Old column names kept for backward compatibility
    unreg_emp_id TEXT,
    unreg_name TEXT,
    unreg_department TEXT,

    department_id INTEGER REFERENCES departments(id),
    date DATE NOT NULL,
    planned_out TIME NOT NULL,
    planned_in TIME NOT NULL,
    actual_out TIME,
    actual_in TIME,

    note TEXT,
    created_by_role TEXT,

    status TEXT NOT NULL,
    appeal_used BOOLEAN NOT NULL DEFAULT FALSE,
    appeal_note TEXT,
    appealed_by_role TEXT,
    appealed_at TIMESTAMP,

    hr_decision TEXT,
    hr_decided_by INTEGER REFERENCES users(id),
    hr_decided_at TIMESTAMP,

    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );`);

  // security logs (OUT/IN history)
  await query(`CREATE TABLE IF NOT EXISTS security_logs(
    id SERIAL PRIMARY KEY,
    leave_id INTEGER REFERENCES leaves(id) ON DELETE CASCADE,
    leave_code TEXT,
    action TEXT NOT NULL CHECK (action IN ('OUT','IN')),
    marked_at TIMESTAMP NOT NULL DEFAULT NOW(),
    marked_by INTEGER REFERENCES users(id),
    note TEXT
  );`);


  // IMPORTANT: if tables already existed, CREATE IF NOT EXISTS won't add new columns -> ALTER
  const alters = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW();`,

    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS note TEXT;`,
    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS created_by_role TEXT;`,
    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS leave_code TEXT;`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_leaves_leave_code ON leaves(leave_code) WHERE leave_code IS NOT NULL;`,
    `CREATE INDEX IF NOT EXISTS idx_security_logs_leave_id ON security_logs(leave_id);`,
    `CREATE INDEX IF NOT EXISTS idx_security_logs_leave_code ON security_logs(leave_code);`,

    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS unregistered_emp_id TEXT;`,
    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS unregistered_name TEXT;`,
    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS unregistered_department TEXT;`,

    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS appealed_by_role TEXT;`,
    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS appealed_at TIMESTAMP;`,

    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS hr_decision TEXT;`,
    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS hr_decided_by INTEGER REFERENCES users(id);`,
    `ALTER TABLE leaves ADD COLUMN IF NOT EXISTS hr_decided_at TIMESTAMP;`
  ];
  for (const sql of alters) {
    try { await query(sql); } catch(e) {}
  }

  // Copy old -> new (if old cols exist)
  try{
    await query(`
      UPDATE leaves
      SET unregistered_emp_id = COALESCE(unregistered_emp_id, unreg_emp_id),
          unregistered_name = COALESCE(unregistered_name, unreg_name),
          unregistered_department = COALESCE(unregistered_department, unreg_department)
      WHERE (unregistered_emp_id IS NULL OR unregistered_name IS NULL OR unregistered_department IS NULL);
    `);
  }catch(e){}

  // notifications + audit_logs (routes use them)
  await query(`CREATE TABLE IF NOT EXISTS notifications(
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT,
    link TEXT,
    meta JSONB,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );`).catch(()=>{});

  await query(`CREATE TABLE IF NOT EXISTS audit_logs(
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    role TEXT,
    action TEXT NOT NULL,
    entity TEXT,
    entity_id INTEGER,
    ip TEXT,
    user_agent TEXT,
    meta JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );`).catch(()=>{});

  // Enforce allowed status transitions at DB level (prevents direct DB edits)
  try{
    await query(`
      CREATE OR REPLACE FUNCTION enforce_leave_status_transition()
      RETURNS trigger AS $$
      BEGIN
        IF TG_OP = 'INSERT' THEN
          IF NEW.status NOT IN ('PENDING_HOD','PENDING_ADMIN','PENDING_HR') THEN
            RAISE EXCEPTION 'Invalid initial status %', NEW.status;
          END IF;
          RETURN NEW;
        END IF;

        IF NEW.status = OLD.status THEN
          RETURN NEW;
        END IF;

        IF OLD.status = 'PENDING_HOD' AND NEW.status IN ('FINAL_APPROVED','REJECTED_HOD') THEN
          RETURN NEW;
        ELSIF OLD.status = 'PENDING_ADMIN' AND NEW.status IN ('FINAL_APPROVED','REJECTED_ADMIN') THEN
          RETURN NEW;
        ELSIF OLD.status = 'PENDING_HR' AND NEW.status IN ('FINAL_APPROVED','FINAL_REJECTED') THEN
          RETURN NEW;
        ELSIF OLD.status IN ('REJECTED_HOD','REJECTED_ADMIN') AND NEW.status = 'APPEAL_PENDING_HR' THEN
          RETURN NEW;
        ELSIF OLD.status = 'APPEAL_PENDING_HR' AND NEW.status IN ('FINAL_APPROVED','FINAL_REJECTED') THEN
          RETURN NEW;
        ELSIF OLD.status = 'FINAL_APPROVED' AND NEW.status = 'AUTO_CLOSED' THEN
          RETURN NEW;
        ELSE
          RAISE EXCEPTION 'Invalid status transition from % to %', OLD.status, NEW.status;
        END IF;
      END;
      $$ LANGUAGE plpgsql;
    `);
    await query(`DROP TRIGGER IF EXISTS trg_enforce_leave_status_transition ON leaves;`);
    await query(`
      CREATE TRIGGER trg_enforce_leave_status_transition
      BEFORE INSERT OR UPDATE OF status ON leaves
      FOR EACH ROW EXECUTE FUNCTION enforce_leave_status_transition();
    `);
  }catch(e){}

  // Fix sequence if it got out of sync (prevents duplicate departments_pkey)
  try{
    await query(`
      SELECT setval(
        pg_get_serial_sequence('departments','id'),
        COALESCE((SELECT MAX(id) FROM departments), 0) + 1,
        false
      );
    `);
  }catch(e){}

  // Seed Admin department safely (no duplicates)
  try{
    await query(`INSERT INTO departments(name)
                 SELECT 'Admin'
                 WHERE NOT EXISTS (SELECT 1 FROM departments WHERE name='Admin');`);
  }catch(e){}
}

ensureSchema().catch(e=>console.error('schema error', e));

// Public departments
router.get('/public/departments', async (req,res)=>{
  const { rows } = await query('SELECT id,name FROM departments ORDER BY name ASC', []);
  res.json({ rows });
});

// Register EMPLOYEE / HOD (PENDING not implemented, simple ACTIVE)
router.post('/auth/register', async (req,res)=>{
  try{
    const { emp_no, full_name, email, password, role, department_id } = req.body || {};
    if(!emp_no || !full_name || !email || !password || !role) {
      return res.status(400).json({ message:'Missing fields' });
    }
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await query(
      `INSERT INTO users(emp_no,full_name,email,password_hash,role,department_id,status)
       VALUES($1,$2,$3,$4,$5,$6,'ACTIVE') RETURNING id,emp_no,full_name,email,role,department_id`,
      [emp_no,full_name,email.toLowerCase(),hash,role.toUpperCase(),department_id||null]
    );
    res.json({ ok:true, user: rows[0] });
  }catch(e){
    console.error(e);
    res.status(400).json({ message:'Register failed' });
  }
});

// Login
router.post('/auth/login', async (req,res)=>{
  try{
    const { email, password } = req.body || {};
    if(!email || !password) return res.status(400).json({ message:'Missing' });
    const user = await getUserByEmail(email);
    if(!user) return res.status(401).json({ message:'Invalid credentials' });
    if(user.status !== 'ACTIVE') return res.status(403).json({ message:'Account not active' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(401).json({ message:'Invalid credentials' });
    const token = signToken(user);
    res.json({ token, me:{ id:user.id, full_name:user.full_name, emp_no:user.emp_no, role:user.role, department_id:user.department_id } });
  }catch(e){
    console.error(e);
    res.status(500).json({ message:'Login error' });
  }
});

// Employee create leave (goes to HOD)

// Employee/HOD/Admin create leave
router.post('/leaves', authMiddleware, async (req,res)=>{
  try{
    const me = await getUserById(req.user.id);
    if(!me) return res.status(401).json({ message:'No user' });

    const role = (me.role||'').toUpperCase();
    const { date, out_time, in_time, note } = req.body || {};
    if(!date || !out_time || !in_time) return res.status(400).json({ message:'Missing fields' });

    // ----------------------
    // DATE & TIME VALIDATION
    // ----------------------
    const nowSL = slNowColombo(); // { date, time }

    // block past dates
    if (date < nowSL.date) {
      return res.status(400).json({ message: 'Past date leave requests are not allowed' });
    }

    // block past time for today (out_time must be in the future)
    if (date === nowSL.date && out_time <= nowSL.time) {
      return res.status(400).json({ message: 'Past time leave requests are not allowed' });
    }

    let status = 'PENDING_HOD';
    let is_hod_request = false;

    const hrAutoApproveEnabled = String(process.env.HR_AUTO_APPROVE || '').toLowerCase() === 'true';
    const hrMainEmpNo = String(process.env.HR_MAIN_EMP_NO || '').trim();
    const isHrMain = role === 'HR'
      && hrAutoApproveEnabled
      && hrMainEmpNo
      && String(me.emp_no || '').trim() === hrMainEmpNo;

    // ✅ HR main auto-approve: start pending (DB trigger rule), then finalize via UPDATE
    if (isHrMain) {
      status = 'PENDING_HR';
    }
    // Normal flows
    else if (role === 'HOD') {
      status = 'PENDING_ADMIN';
      is_hod_request = true;
    }
    else if (role === 'ADMIN') {
      status = 'PENDING_HR';
    }
    else if (role === 'HR') {
      // Non-main HR users behave like employees by default
      status = 'PENDING_HOD';
    }

    const leave_code = await generateLeaveCode();

    const r = await query(
      `INSERT INTO leaves(leave_code,employee_id,department_id,date,planned_out,planned_in,note,status,created_by_role,is_hod_request,is_unregistered)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,FALSE)
       RETURNING id,leave_code,date,planned_out AS out_time,planned_in AS in_time,note,status`,
      [leave_code, me.id, me.department_id || null, date, out_time, in_time, (note||null), status, role, is_hod_request]
    );

    // ✅ HR main auto-approve: finalize via UPDATE so DB trigger allows it
    if (isHrMain) {
      await query(
        `UPDATE leaves
         SET status='FINAL_APPROVED', hr_decision='APPROVED', hr_decided_by=$2, hr_decided_at=NOW()
         WHERE id=$1 AND status='PENDING_HR'`,
        [r.rows[0].id, me.id]
      );

      // Optional: notify SECURITY so they can mark OUT/IN
      await notifyRole('SECURITY', {
        title: 'Leave Ready for OUT/IN',
        body: `An approved leave is ready for OUT/IN marking (Leave #${r.rows[0].id}).`,
        meta: { leave_id: r.rows[0].id }
      });

      await logAudit(req, 'HR_AUTO_APPROVE', 'leaves', r.rows[0].id, { status_from: 'PENDING_HR', status_to: 'FINAL_APPROVED' });

      return res.status(201).json({ ...r.rows[0], status: 'FINAL_APPROVED' });
    }

    // notify next approver(s)
    await notifyByStatus(status, me.department_id || null, {
      title: 'New Leave Request',
      body: `${me.full_name} submitted a leave request for ${date} (${out_time} - ${in_time}).`,
      link: null,
      meta: { leave_id: r.rows[0].id, status }
    });

    await logAudit(req, 'LEAVE_CREATE', 'leaves', r.rows[0].id, { status });

    res.status(201).json(r.rows[0]);
  }catch(e){
    console.error(e);
    res.status(500).json({ message:'Create leave error' });
  }
});

router.get('/leaves/mine', authMiddleware, async (req,res)=>{
  const { rows } = await query(
    `SELECT l.*, d.name AS department_name, u.emp_no, u.full_name
     FROM leaves l
     LEFT JOIN departments d ON d.id=l.department_id
     LEFT JOIN users u ON u.id=l.employee_id
     WHERE l.employee_id=$1
     ORDER BY l.id DESC`,
    [req.user.id]
  );
  res.json({ rows });
});

// HOD pending (employee requests)
router.get('/hod/pending', authMiddleware, requireRole('HOD'), async (req,res)=>{
  const me = await getUserById(req.user.id);
  const { rows } = await query(
    `SELECT l.*, u.emp_no, u.full_name
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     WHERE l.department_id=$1 AND l.status='PENDING_HOD'`,
    [me.department_id]
  );
  res.json({ rows });
});

router.post('/hod/approve/:id', authMiddleware, requireRole('HOD'), async (req,res)=>{
  const id = Number(req.params.id);
  await query(
    `UPDATE leaves SET status='FINAL_APPROVED' WHERE id=$1 AND status='PENDING_HOD'`,
    [id]
  );
  const info = await query(`SELECT l.id,l.date,l.planned_out,l.planned_in,u.id as uid,u.email,u.full_name FROM leaves l LEFT JOIN users u ON u.id=l.employee_id WHERE l.id=$1`, [id]);
  if(info.rows[0]?.uid){
    await notifyUsers([info.rows[0].uid], { title:'Leave Approved', body:`Your leave for ${info.rows[0].date} was approved by HOD.`, meta:{leave_id:id} });
  }
  await logAudit(req,'HOD_APPROVE','leaves',id,null);

  res.json({ ok:true });
});

router.post('/hod/reject/:id', authMiddleware, requireRole('HOD'), async (req,res)=>{
  const id = Number(req.params.id);
  await query(
    `UPDATE leaves SET status='REJECTED_HOD' WHERE id=$1 AND status='PENDING_HOD'`,
    [id]
  );
  const info = await query(`SELECT l.id,l.date,u.id as uid FROM leaves l LEFT JOIN users u ON u.id=l.employee_id WHERE l.id=$1`, [id]);
  if(info.rows[0]?.uid){ await notifyUsers([info.rows[0].uid], { title:'Leave Rejected', body:`Your leave for ${info.rows[0].date} was rejected by HOD. You may appeal once.`, meta:{leave_id:id} }); }
  await logAudit(req,'HOD_REJECT','leaves',id,null);

  res.json({ ok:true });
});

// Admin pending (HOD requests)
router.get('/admin/pending', authMiddleware, requireRole('ADMIN'), async (req,res)=>{
  const { rows } = await query(
    `SELECT l.*, u.emp_no, u.full_name
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     WHERE l.is_hod_request=TRUE AND l.status='PENDING_ADMIN'
     ORDER BY l.id ASC`,
    []
  );
  res.json({ rows });
});

router.post('/admin/approve/:id', authMiddleware, requireRole('ADMIN'), async (req,res)=>{
  const id = Number(req.params.id);
  await query(
    `UPDATE leaves SET status='FINAL_APPROVED' WHERE id=$1 AND status='PENDING_ADMIN'`,
    [id]
  );
  const info = await query(`SELECT l.id,l.date,u.id as uid,d.name AS dept FROM leaves l LEFT JOIN users u ON u.id=l.employee_id LEFT JOIN departments d ON d.id=l.department_id WHERE l.id=$1`, [id]);
  if(info.rows[0]?.uid){ await notifyUsers([info.rows[0].uid], { title:'Leave Approved', body:`Your leave for ${info.rows[0].date} was approved by Admin.`, meta:{leave_id:id} }); }
  await notifyRole('SECURITY', { title:'Leave Ready for OUT/IN', body:`An approved leave is ready for OUT/IN marking (Leave #${id}).`, meta:{leave_id:id} });
  await logAudit(req,'ADMIN_APPROVE','leaves',id,null);

  res.json({ ok:true });
});

router.post('/admin/reject/:id', authMiddleware, requireRole('ADMIN'), async (req,res)=>{
  const id = Number(req.params.id);
  await query(
    `UPDATE leaves SET status='REJECTED_ADMIN' WHERE id=$1 AND status='PENDING_ADMIN'`,
    [id]
  );
  const info = await query(`SELECT l.id,l.date,u.id as uid FROM leaves l LEFT JOIN users u ON u.id=l.employee_id WHERE l.id=$1`, [id]);
  if(info.rows[0]?.uid){ await notifyUsers([info.rows[0].uid], { title:'Leave Rejected', body:`Your leave for ${info.rows[0].date} was rejected by Admin.`, meta:{leave_id:id} }); }
  await logAudit(req,'ADMIN_REJECT','leaves',id,null);

  res.json({ ok:true });
});

// Appeal (one time)
router.post('/leaves/:id/appeal', authMiddleware, async (req,res)=>{
  const id = Number(req.params.id);
  const { note } = req.body || {};
  const { rows } = await query(`SELECT * FROM leaves WHERE id=$1`, [id]);
  const l = rows[0];
  if(!l) return res.status(404).json({ message:'Not found' });
  if(l.employee_id !== req.user.id) return res.status(403).json({ message:'Not owner' });
  if(l.appeal_used) return res.status(400).json({ message:'Appeal already used' });
  if(!['REJECTED_HOD','REJECTED_ADMIN'].includes(l.status)) {
    return res.status(400).json({ message:'Cannot appeal this status' });
  }
  await query(
    `UPDATE leaves SET appeal_used=TRUE, appeal_note=$2, status='APPEAL_PENDING_HR' WHERE id=$1`,
    [id, note||null]
  );
  res.json({ ok:true });
});

// HR / ADMIN can override APPEAL_PENDING_HR
router.get('/hr/appeals', authMiddleware, requireRole('HR'), async (req,res)=>{
  const { rows } = await query(`SELECT l.*, u.emp_no, u.full_name FROM leaves l LEFT JOIN users u ON u.id=l.employee_id WHERE l.status='APPEAL_PENDING_HR'`,[]);
  res.json({ rows });
});

router.post('/hr/appeals/:id/approve', authMiddleware, requireRole('HR'), async (req,res)=>{
  const id = Number(req.params.id);
  await query(`UPDATE leaves SET status='FINAL_APPROVED' WHERE id=$1 AND status='APPEAL_PENDING_HR'`,[id]);
  res.json({ ok:true });
});

router.post('/hr/appeals/:id/reject', authMiddleware, requireRole('HR'), async (req,res)=>{
  const id = Number(req.params.id);
  await query(`UPDATE leaves SET status='FINAL_REJECTED' WHERE id=$1 AND status='APPEAL_PENDING_HR'`,[id]);
  res.json({ ok:true });
});

// Admin appeals endpoints removed: appeals handled by HR only
router.get('/admin/appeals', authMiddleware, requireRole('ADMIN'), (req,res)=>res.status(410).json({ message: 'Deprecated. Appeals are handled by HR.' }));
router.post('/admin/appeals/:id/approve', authMiddleware, requireRole('ADMIN'), (req,res)=>res.status(410).json({ message: 'Deprecated. Appeals are handled by HR.' }));
router.post('/admin/appeals/:id/reject', authMiddleware, requireRole('ADMIN'), (req,res)=>res.status(410).json({ message: 'Deprecated. Appeals are handled by HR.' }));

// Security pending approved
router.get('/security/pending', authMiddleware, requireRole('SECURITY'), async (req,res)=>{
  const { rows } = await query(
    `SELECT l.*, u.emp_no, u.full_name
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     WHERE l.status='FINAL_APPROVED'
       AND (l.actual_out IS NULL OR l.actual_in IS NULL)
     ORDER BY l.date ASC, l.id ASC`,
    []
  );
  res.json({ rows });
});


router.get('/security/code/:code', authMiddleware, requireRole('SECURITY'), async (req,res)=>{
  const code = String(req.params.code || '').trim();
  if(!/^[0-9]{6}$/.test(code)) return res.status(400).json({ message:'Invalid code (6 digits)' });

  const { rows } = await query(
    `SELECT l.*, u.emp_no, u.full_name, d.name AS department_name
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     LEFT JOIN departments d ON d.id=l.department_id
     WHERE l.leave_code=$1
     LIMIT 1`,
    [code]
  );
  if(!rows[0]) return res.status(404).json({ message:'Leave not found for this code' });
  res.json({ row: rows[0] });
});

router.post('/security/code/:code/out', authMiddleware, requireRole('SECURITY'), async (req,res)=>{
  const code = String(req.params.code || '').trim();
  if(!/^[0-9]{6}$/.test(code)) return res.status(400).json({ message:'Invalid code (6 digits)' });
  const now = slNowColombo();

  const upd = await query(
    `UPDATE leaves SET actual_out=$2 WHERE leave_code=$1 AND status='FINAL_APPROVED' RETURNING id`,
    [code, now.time]
  );
  if(!upd.rows[0]) return res.status(404).json({ message:'Leave not found / not approved' });

  const id = upd.rows[0].id;
  await query(
    `INSERT INTO security_logs(leave_id, leave_code, action, marked_by) VALUES($1,$2,'OUT',$3)`,
    [id, code, req.user.id]
  );

  const info = await query(`SELECT employee_id,date FROM leaves WHERE id=$1`, [id]);
  if(info.rows[0]?.employee_id){
    await notifyUsers([info.rows[0].employee_id], { type:'SECURITY_OUT', text:`Security marked OUT for leave on ${info.rows[0].date}.`, meta:{leave_id:id, leave_code:code} });
  }
  await logAudit(req,'SECURITY_OUT_CODE','leaves',id,{ leave_code: code });

  res.json({ ok:true, time: now.time, leave_id: id });
});

router.post('/security/code/:code/in', authMiddleware, requireRole('SECURITY'), async (req,res)=>{
  const code = String(req.params.code || '').trim();
  if(!/^[0-9]{6}$/.test(code)) return res.status(400).json({ message:'Invalid code (6 digits)' });
  const now = slNowColombo();

  const upd = await query(
    `UPDATE leaves SET actual_in=$2 WHERE leave_code=$1 AND status='FINAL_APPROVED' RETURNING id`,
    [code, now.time]
  );
  if(!upd.rows[0]) return res.status(404).json({ message:'Leave not found / not approved' });

  const id = upd.rows[0].id;
  await query(
    `INSERT INTO security_logs(leave_id, leave_code, action, marked_by) VALUES($1,$2,'IN',$3)`,
    [id, code, req.user.id]
  );

  const info = await query(`SELECT employee_id,date FROM leaves WHERE id=$1`, [id]);
  if(info.rows[0]?.employee_id){
    await notifyUsers([info.rows[0].employee_id], { type:'SECURITY_IN', text:`Security marked IN for leave on ${info.rows[0].date}.`, meta:{leave_id:id, leave_code:code} });
  }
  await logAudit(req,'SECURITY_IN_CODE','leaves',id,{ leave_code: code });

  res.json({ ok:true, time: now.time, leave_id: id });
});
router.post('/security/:id/out', authMiddleware, requireRole('SECURITY'), async (req,res)=>{
  const id = Number(req.params.id);
  const now = slNowColombo();
  await query(
    `UPDATE leaves SET actual_out=$2 WHERE id=$1 AND status='FINAL_APPROVED'`,
    [id, now.time]
  );
  await query(`INSERT INTO security_logs(leave_id, leave_code, action, marked_by) SELECT id, leave_code, 'OUT', $2 FROM leaves WHERE id=$1`, [id, req.user.id]);
  const info = await query(`SELECT employee_id,date FROM leaves WHERE id=$1`, [id]);
  if(info.rows[0]?.employee_id){ await notifyUsers([info.rows[0].employee_id], { title:'Marked OUT', body:`Security marked you OUT for leave on ${info.rows[0].date}.`, meta:{leave_id:id} }); }
  await logAudit(req,'SECURITY_OUT','leaves',id,null);

  res.json({ ok:true, time: now.time });
});

router.post('/security/:id/in', authMiddleware, requireRole('SECURITY'), async (req,res)=>{
  const id = Number(req.params.id);
  const now = slNowColombo();
  await query(
    `UPDATE leaves SET actual_in=$2 WHERE id=$1 AND status='FINAL_APPROVED'`,
    [id, now.time]
  );
  await query(`INSERT INTO security_logs(leave_id, leave_code, action, marked_by) SELECT id, leave_code, 'IN', $2 FROM leaves WHERE id=$1`, [id, req.user.id]);
  const info = await query(`SELECT employee_id,date FROM leaves WHERE id=$1`, [id]);
  if(info.rows[0]?.employee_id){ await notifyUsers([info.rows[0].employee_id], { title:'Marked IN', body:`Security marked you IN for leave on ${info.rows[0].date}.`, meta:{leave_id:id} }); }
  await logAudit(req,'SECURITY_IN','leaves',id,null);

  res.json({ ok:true, time: now.time });
});

// Manual auto-close endpoint (run from cron or sometimes manually)
router.post('/admin/run-autoclose', authMiddleware, requireRole('ADMIN','HR'), async (req,res)=>{
  const now = slNowColombo();
  // close any FINAL_APPROVED today with OUT but no IN after 21:30
  if (now.time < '21:30') {
    return res.json({ ok:true, message:'Before 21:30, nothing done' });
  }
  const result = await query(
    `UPDATE leaves
     SET actual_in='21:30', status='AUTO_CLOSED'
     WHERE date=$1 AND status='FINAL_APPROVED' AND actual_out IS NOT NULL AND actual_in IS NULL
     RETURNING id`,
    [now.date]
  );
  res.json({ ok:true, closed: result.rows.length });
});


/* =========================
   COMPATIBILITY ALIASES (old frontend paths)
========================= */

// Frontend older build uses /leave/* paths

// Compatibility alias for older frontend
router.post('/leave/request', (req,res)=>res.status(410).json({ message:'Deprecated. Use /api/leaves' }));


router.get('/leave/mine', (req,res)=>res.status(410).json({ message:'Deprecated. Use /api/leaves/mine' }));

router.post('/leave/appeal/:id', (req,res)=>res.status(410).json({ message:'Deprecated. Use /api/leaves/:id/appeal' }));

/* =========================
   HR: ADMIN REQUESTS (PENDING_HR)
========================= */

router.get('/hr/pending', authMiddleware, requireRole('HR'), async (req,res)=>{
  const r = await query(
    `SELECT l.id, l.date, l.planned_out, l.planned_in, l.note, l.status,
            u.emp_no, u.full_name, u.email, u.role, d.name AS department_name
     FROM leaves l
     JOIN users u ON u.id=l.employee_id
     LEFT JOIN departments d ON d.id=l.department_id
     WHERE l.status='PENDING_HR'
     ORDER BY l.created_at ASC
     LIMIT 800`
  );
  res.json(r.rows);
});

router.post('/hr/approve/:id', authMiddleware, requireRole('HR'), async (req,res)=>{
  const id = Number(req.params.id);
  const me = req.user;
  const r = await query(`SELECT * FROM leaves WHERE id=$1`, [id]);
  const leave = r.rows[0];
  if(!leave) return res.status(404).json({ message:'Not found' });
  if(leave.status !== 'PENDING_HR') return res.status(400).json({ message:'Not PENDING_HR' });

  await query(
    `UPDATE leaves
     SET status='FINAL_APPROVED', hr_decision='APPROVED', hr_decided_by=$2, hr_decided_at=NOW()
     WHERE id=$1`,
    [id, me.id]
  );
  if(leave?.employee_id){ await notifyUsers([leave.employee_id], { title:'Leave Approved', body:`Your leave for ${leave.date} was approved by HR.`, meta:{leave_id:id} }); }
  await notifyRole('SECURITY', { title:'Leave Ready for OUT/IN', body:`An approved leave is ready for OUT/IN marking (Leave #${id}).`, meta:{leave_id:id} });
  await logAudit(req,'HR_APPROVE','leaves',id,null);

  res.json({ ok:true });
});

router.post('/hr/reject/:id', authMiddleware, requireRole('HR'), async (req,res)=>{
  const id = Number(req.params.id);
  const me = req.user;
  const r = await query(`SELECT * FROM leaves WHERE id=$1`, [id]);
  const leave = r.rows[0];
  if(!leave) return res.status(404).json({ message:'Not found' });
  if(leave.status !== 'PENDING_HR') return res.status(400).json({ message:'Not PENDING_HR' });

  await query(
    `UPDATE leaves
     SET status='FINAL_REJECTED', hr_decision='REJECTED', hr_decided_by=$2, hr_decided_at=NOW()
     WHERE id=$1`,
    [id, me.id]
  );
  if(leave?.employee_id){ await notifyUsers([leave.employee_id], { title:'Leave Rejected', body:`Your leave for ${leave.date} was rejected by HR.`, meta:{leave_id:id} }); }
  await logAudit(req,'HR_REJECT','leaves',id,null);

  res.json({ ok:true });
});

/* =========================
   HR: UNREGISTERED LEAVE (must pick department)
========================= */

router.post('/hr/unregistered', authMiddleware, requireRole('HR'), async (req,res)=>{
  const body = req.body || {};
  const emp_id = String(body.emp_id || '').trim().slice(0,50) || null;
  const name = String(body.name || '').trim().slice(0,120);
  const department_id = Number(body.department_id || 0);
  const date = String(body.date || '').trim();
  const out_time = String(body.out_time || '').trim();
  const in_time = String(body.in_time || '').trim();
  const note = String(body.note || '').trim().slice(0,300) || null;

  if(!name) return res.status(400).json({ message:'Name required' });
  if(!department_id) return res.status(400).json({ message:'department_id required' });
  if(!date || !out_time || !in_time) return res.status(400).json({ message:'date/out_time/in_time required' });

  const d = await query(`SELECT name FROM departments WHERE id=$1`, [department_id]);
  if(!d.rows[0]) return res.status(400).json({ message:'Invalid department' });

  const leave_code = await generateLeaveCode();

  const r = await query(
    `INSERT INTO leaves(leave_code,employee_id,department_id,date,planned_out,planned_in,note,status,created_by_role,is_unregistered,unregistered_emp_id,unregistered_name,unregistered_department)
     VALUES($1,NULL,$2,$3,$4,$5,$6,'PENDING_HOD','HR',TRUE,$7,$8,$9)
     RETURNING id,leave_code,date,planned_out,planned_in,note,status,unregistered_emp_id,unregistered_name,unregistered_department`,
    [leave_code, department_id, date, out_time, in_time, note, emp_id, name, d.rows[0]['name']]
  );
  res.status(201).json(r.rows[0]);
});

/* =========================
   ADMIN/HR: USER APPROVAL
========================= */

router.get('/admin/pending-users', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const r = await query(
    `SELECT id, emp_no, full_name, email, role, department_id, status, created_at
     FROM users
     WHERE status='PENDING'
     ORDER BY created_at ASC
     LIMIT 500`
  );
  res.json(r.rows);
});

router.post('/admin/approve-user/:id', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const id = Number(req.params.id);
  const r = await query(`SELECT id,status FROM users WHERE id=$1`, [id]);
  const u = r.rows[0];
  if(!u) return res.status(404).json({ message:'User not found' });
  if(u.status !== 'PENDING') return res.status(400).json({ message:'User not pending' });
  await query(`UPDATE users SET status='ACTIVE' WHERE id=$1`, [id]);
  res.json({ ok:true });
});

router.post('/admin/reject-user/:id', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const id = Number(req.params.id);
  const r = await query(`SELECT id,status FROM users WHERE id=$1`, [id]);
  const u = r.rows[0];
  if(!u) return res.status(404).json({ message:'User not found' });
  if(u.status !== 'PENDING') return res.status(400).json({ message:'User not pending' });
  await query(`UPDATE users SET status='REJECTED' WHERE id=$1`, [id]);
  res.json({ ok:true });
});

/* =========================
   REPORTS: INSIGHTS (TOP LEAVE TAKERS)
========================= */

router.get('/reports/insights', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const period = String(req.query.period || 'week').toLowerCase();
  let startSql = "((now() AT TIME ZONE 'Asia/Colombo')::date - INTERVAL '6 day')::date";
  if(period === 'month') startSql = "date_trunc('month', (now() AT TIME ZONE 'Asia/Colombo'))::date";
  if(period === 'year')  startSql = "date_trunc('year', (now() AT TIME ZONE 'Asia/Colombo'))::date";

  const topMinutes = await query(
    `SELECT u.id, u.emp_no, u.full_name,
            COUNT(*)::int AS requests,
            COUNT(DISTINCT l.date)::int AS days,
            COALESCE(SUM(
              CASE
                WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                  THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                ELSE EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60
              END
            ),0)::int AS minutes
     FROM leaves l
     JOIN users u ON u.id=l.employee_id
     WHERE l.status='FINAL_APPROVED'
       AND l.date >= ${startSql}
       AND l.employee_id IS NOT NULL
     GROUP BY u.id, u.emp_no, u.full_name
     ORDER BY minutes DESC
     LIMIT 10`
  );

  const topRequests = await query(
    `SELECT u.id, u.emp_no, u.full_name,
            COUNT(*)::int AS requests,
            COUNT(DISTINCT l.date)::int AS days,
            COALESCE(SUM(
              CASE
                WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                  THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                ELSE EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60
              END
            ),0)::int AS minutes
     FROM leaves l
     JOIN users u ON u.id=l.employee_id
     WHERE l.status='FINAL_APPROVED'
       AND l.date >= ${startSql}
       AND l.employee_id IS NOT NULL
     GROUP BY u.id, u.emp_no, u.full_name
     ORDER BY requests DESC, minutes DESC
     LIMIT 10`
  );

  res.json({
    period,
    top_by_minutes: topMinutes.rows,
    top_by_requests: topRequests.rows
  });
});


// --------------------
// Notifications
// --------------------
router.get('/notifications', authMiddleware, async (req,res)=>{
  const unread = String(req.query.unread||'').trim() === '1';
  const where = unread ? "AND is_read=FALSE" : "";
  const r = await query(
    `SELECT id,title,body,link,meta,is_read,created_at
     FROM notifications
     WHERE user_id=$1 ${where}
     ORDER BY created_at DESC
     LIMIT 80`,
    [req.user.id]
  );
  const c = await query(`SELECT COUNT(*)::int AS unread FROM notifications WHERE user_id=$1 AND is_read=FALSE`, [req.user.id]);
  res.json({ unread: c.rows[0]?.unread || 0, rows: r.rows });
});

router.post('/notifications/:id/read', authMiddleware, async (req,res)=>{
  const id = Number(req.params.id);
  await query(`UPDATE notifications SET is_read=TRUE WHERE id=$1 AND user_id=$2`, [id, req.user.id]);
  await logAudit(req,'NOTIF_READ','notifications',id,null);
  res.json({ ok:true });
});

router.post('/notifications/read-all', authMiddleware, async (req,res)=>{
  await query(`UPDATE notifications SET is_read=TRUE WHERE user_id=$1 AND is_read=FALSE`, [req.user.id]);
  await logAudit(req,'NOTIF_READ_ALL','notifications',null,null);
  res.json({ ok:true });
});

// --------------------
// Dashboard summary (HR/ADMIN)
// --------------------
router.get('/dashboard/summary', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const today = "(now() AT TIME ZONE 'Asia/Colombo')::date";

  const statusCounts = await query(
    `SELECT status, COUNT(*)::int AS count
     FROM leaves
     GROUP BY status
     ORDER BY status`
  );

  const todayTotals = await query(
    `SELECT COUNT(*)::int AS requests,
            COALESCE(SUM(EXTRACT(EPOCH FROM (planned_in - planned_out))/60),0)::int AS planned_minutes
     FROM leaves
     WHERE date = ${today}`
  );

  const securityPending = await query(
    `SELECT COUNT(*)::int AS count
     FROM leaves
     WHERE status='FINAL_APPROVED'
       AND (actual_out IS NULL OR actual_in IS NULL)`
  );

  const recent = await query(
    `SELECT l.id,l.date,l.planned_out,l.planned_in,l.status,l.is_unregistered,
            COALESCE(u.emp_no,l.unregistered_emp_id) AS emp_no,
            COALESCE(u.full_name,l.unregistered_name) AS full_name,
            d.name AS department_name,
            l.created_at
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     LEFT JOIN departments d ON d.id=l.department_id
     ORDER BY l.created_at DESC
     LIMIT 15`
  );

  res.json({
    today: null,
    today_totals: todayTotals.rows[0],
    status_counts: statusCounts.rows,
    security_pending: securityPending.rows[0]?.count || 0,
    recent: recent.rows
  });
});

// --------------------
// Reports (HR/ADMIN)
// --------------------

// Daily (supports filters + pagination)
router.get('/reports/daily', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const q = req.query || {};
  const date = String(q.date || '').trim();
  if (date && !isISODate(date)) return res.status(400).json({ message:'Invalid date (YYYY-MM-DD)' });

  const department_id = parseIntParam(q.department_id);
  const unregistered = parseBoolParam(q.unregistered);
  const emp_no = String(q.emp_no || '').trim();
  const statuses = parseStatusList(q.status);

  const limit = Math.min(Math.max(parseIntParam(q.limit, 200), 1), 1000);
  const offset = Math.max(parseIntParam(q.offset, 0) || 0, 0);

  const dayExpr = date ? '$1::date' : "(now() AT TIME ZONE 'Asia/Colombo')::date";
  const params = [];
  let i = 1;
  if (date){ params.push(date); i++; }

  const where = [`l.date = ${dayExpr}`];
  if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
  if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
  if (emp_no){ where.push(`COALESCE(u.emp_no, l.unregistered_emp_id) ILIKE $${i++}`); params.push(`%${emp_no}%`); }
  if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }

  const sqlWhere = where.length ? ('WHERE ' + where.join(' AND ')) : '';

  const baseSelect = `
     SELECT l.id,l.leave_code,l.date,l.planned_out,l.planned_in,l.actual_out,l.actual_in,l.status,l.note,l.is_unregistered,
            COALESCE(u.emp_no,l.unregistered_emp_id) AS emp_no,
            COALESCE(u.full_name,l.unregistered_name) AS full_name,
            d.name AS department_name,
            EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60 AS planned_minutes,
            CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                 THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                 ELSE NULL
            END AS actual_minutes,
            l.created_at
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     LEFT JOIN departments d ON d.id=l.department_id
  `;

  const rows = await query(
    `${baseSelect} ${sqlWhere} ORDER BY l.created_at ASC LIMIT $${i++} OFFSET $${i++}`,
    params.concat([limit, offset])
  );

  const total = await query(
    `SELECT COUNT(*)::int AS total FROM leaves l LEFT JOIN users u ON u.id=l.employee_id ${sqlWhere}`,
    params
  );

  const summary = await query(
    `SELECT l.status, COUNT(*)::int AS count
     FROM leaves l LEFT JOIN users u ON u.id=l.employee_id
     ${sqlWhere}
     GROUP BY l.status
     ORDER BY l.status`,
    params
  );

  res.json({
    date: date || null,
    filters: { department_id: department_id || null, emp_no: emp_no || null, status: statuses || null, unregistered },
    pagination: { limit, offset, total: total.rows[0]?.total || 0 },
    summary: summary.rows,
    rows: rows.rows
  });
});

// Monthly aggregation (supports filters; includes unregistered grouped as emp_no)
router.get('/reports/monthly', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const q = req.query || {};
  const year = Number(q.year);
  const month = Number(q.month);
  if(!year || !month) return res.status(400).json({ message:'year and month required' });

  const department_id = parseIntParam(q.department_id);
  const unregistered = parseBoolParam(q.unregistered);
  const emp_no = String(q.emp_no || '').trim();
  const statuses = parseStatusList(q.status);

  const start = `${year}-${String(month).padStart(2,'0')}-01`;
  const params = [start];
  let i = 2;
  const where = [
    `l.date >= $1::date`,
    `l.date < ($1::date + INTERVAL '1 month')`
  ];
  if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
  if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
  if (emp_no){ where.push(`COALESCE(u.emp_no, l.unregistered_emp_id) ILIKE $${i++}`); params.push(`%${emp_no}%`); }
  if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }
  const sqlWhere = 'WHERE ' + where.join(' AND ');

  const emp = await query(
    `SELECT
        COALESCE(u.emp_no, l.unregistered_emp_id, '—') AS emp_no,
        COALESCE(u.full_name, l.unregistered_name, 'Unregistered') AS full_name,
        BOOL_OR(l.is_unregistered) AS is_unregistered,
        COUNT(*)::int AS requests,
        COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
        COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                          THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                          ELSE 0 END),0)::int AS actual_minutes
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     ${sqlWhere}
     GROUP BY emp_no, full_name
     ORDER BY planned_minutes DESC, requests DESC
     LIMIT 100`,
    params
  );

  const dept = await query(
    `SELECT d.id, COALESCE(d.name,'—') AS name,
            COUNT(*)::int AS requests,
            COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
            COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                          THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                          ELSE 0 END),0)::int AS actual_minutes
     FROM leaves l
     LEFT JOIN departments d ON d.id=l.department_id
     LEFT JOIN users u ON u.id=l.employee_id
     ${sqlWhere}
     GROUP BY d.id, name
     ORDER BY planned_minutes DESC, requests DESC`,
    params
  );

  res.json({ year, month, filters: { department_id: department_id||null, emp_no: emp_no||null, status: statuses||null, unregistered }, by_employee: emp.rows, by_department: dept.rows });
});

// Yearly aggregation (supports filters; includes unregistered grouped as emp_no)
router.get('/reports/yearly', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const q = req.query || {};
  const year = Number(q.year);
  if(!year) return res.status(400).json({ message:'year required' });

  const department_id = parseIntParam(q.department_id);
  const unregistered = parseBoolParam(q.unregistered);
  const emp_no = String(q.emp_no || '').trim();
  const statuses = parseStatusList(q.status);

  const start = `${year}-01-01`;
  const params = [start];
  let i = 2;
  const where = [
    `l.date >= $1::date`,
    `l.date < ($1::date + INTERVAL '1 year')`
  ];
  if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
  if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
  if (emp_no){ where.push(`COALESCE(u.emp_no, l.unregistered_emp_id) ILIKE $${i++}`); params.push(`%${emp_no}%`); }
  if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }
  const sqlWhere = 'WHERE ' + where.join(' AND ');

  const emp = await query(
    `SELECT
        COALESCE(u.emp_no, l.unregistered_emp_id, '—') AS emp_no,
        COALESCE(u.full_name, l.unregistered_name, 'Unregistered') AS full_name,
        BOOL_OR(l.is_unregistered) AS is_unregistered,
        COUNT(*)::int AS requests,
        COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
        COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                          THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                          ELSE 0 END),0)::int AS actual_minutes
     FROM leaves l
     LEFT JOIN users u ON u.id=l.employee_id
     ${sqlWhere}
     GROUP BY emp_no, full_name
     ORDER BY planned_minutes DESC, requests DESC
     LIMIT 200`,
    params
  );

  const dept = await query(
    `SELECT d.id, COALESCE(d.name,'—') AS name,
            COUNT(*)::int AS requests,
            COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
            COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                          THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                          ELSE 0 END),0)::int AS actual_minutes
     FROM leaves l
     LEFT JOIN departments d ON d.id=l.department_id
     LEFT JOIN users u ON u.id=l.employee_id
     ${sqlWhere}
     GROUP BY d.id, name
     ORDER BY planned_minutes DESC, requests DESC`,
    params
  );

  res.json({ year, filters: { department_id: department_id||null, emp_no: emp_no||null, status: statuses||null, unregistered }, by_employee: emp.rows, by_department: dept.rows });
});

// Trends (supports filters; planned+actual minutes)
router.get('/reports/trends', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const q = req.query || {};
  const from = String(q.from||'').trim();
  const to = String(q.to||'').trim();
  const group = String(q.group||'day').toLowerCase();

  if(!from || !to) return res.status(400).json({ message:'from and to required (YYYY-MM-DD)' });
  if(!isISODate(from) || !isISODate(to)) return res.status(400).json({ message:'Invalid from/to date (YYYY-MM-DD)' });

  const department_id = parseIntParam(q.department_id);
  const unregistered = parseBoolParam(q.unregistered);
  const statuses = parseStatusList(q.status);

  const bucket = group === 'month' ? "date_trunc('month', l.date)::date" : "l.date";
  const params = [from, to];
  let i = 3;
  const where = [`l.date >= $1::date`, `l.date <= $2::date`];
  if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
  if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
  if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }
  const sqlWhere = 'WHERE ' + where.join(' AND ');

  const r = await query(
    `SELECT ${bucket} AS bucket,
            COUNT(*)::int AS requests,
            COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
            COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                          THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                          ELSE 0 END),0)::int AS actual_minutes
     FROM leaves l
     ${sqlWhere}
     GROUP BY bucket
     ORDER BY bucket ASC`,
    params
  );
  res.json({ from, to, group, filters: { department_id: department_id||null, status: statuses||null, unregistered }, rows: r.rows });
});

// Export (CSV/XLSX) - includes BOM for Excel Sinhala support

// Export (CSV/XLSX) - includes BOM for Excel Sinhala support
router.get('/reports/export', authMiddleware, requireRole('HR','ADMIN'), async (req,res)=>{
  const q = req.query || {};
  const type = String(q.type || 'daily').toLowerCase();   // daily | monthly | yearly | trends
  const format = String(q.format || 'csv').toLowerCase(); // csv | xlsx

  if (!['csv','xlsx'].includes(format)) return res.status(400).json({ message:'format must be csv or xlsx' });
  if (!['daily','monthly','yearly','trends'].includes(type)) return res.status(400).json({ message:'type must be daily, monthly, yearly or trends' });

  // Common filters
  const department_id = parseIntParam(q.department_id);
  const unregistered = parseBoolParam(q.unregistered);
  const emp_no = String(q.emp_no || '').trim();
  const statuses = parseStatusList(q.status);

  // CSV: keep daily-only (simple + reliable). For monthly/yearly/trends use XLSX (multi-sheet / better formatting)
  if (format === 'csv' && type !== 'daily') {
    return res.status(400).json({ message:'CSV export supports Daily only. Use format=xlsx for monthly/yearly/trends.' });
  }

  // --------
  // Helpers (XLSX)
  // --------
  function addMetaSheet(wb, metaObj){
    const ws = wb.addWorksheet('Meta');
    ws.columns = [{ header:'Key', key:'k', width:26 }, { header:'Value', key:'v', width:60 }];
    ws.getRow(1).font = { bold: true };
    ws.views = [{ state:'frozen', ySplit: 1 }];
    Object.entries(metaObj || {}).forEach(([k,v])=>{
      ws.addRow({ k, v: (v===undefined || v===null) ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v)) });
    });
    return ws;
  }

  function styleHeader(ws){
    ws.getRow(1).font = { bold: true };
    ws.views = [{ state:'frozen', ySplit: 1 }];
  }

  // --------
  // DAILY (raw rows)
  // --------
  async function exportDaily(){
    const date = String(q.date || '').trim();
    if (date && !isISODate(date)) return res.status(400).json({ message:'Invalid date (YYYY-MM-DD)' });

    const dayExpr = date ? '$1::date' : "(now() AT TIME ZONE 'Asia/Colombo')::date";
    const params = [];
    let i = 1;
    if (date){ params.push(date); i++; }

    const where = [`l.date = ${dayExpr}`];
    if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
    if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
    if (emp_no){
      where.push(`(COALESCE(u.emp_no, l.unregistered_emp_id) ILIKE $${i++} OR COALESCE(u.full_name, l.unregistered_name) ILIKE $${i++})`);
      params.push(`%${emp_no}%`, `%${emp_no}%`);
    }
    if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }
    const sqlWhere = 'WHERE ' + where.join(' AND ');

    const r = await query(
      `SELECT l.id,l.leave_code,l.date,l.planned_out,l.planned_in,l.actual_out,l.actual_in,l.status,l.note,l.is_unregistered,
              COALESCE(u.emp_no,l.unregistered_emp_id) AS emp_no,
              COALESCE(u.full_name,l.unregistered_name) AS full_name,
              d.name AS department_name,
              EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60 AS planned_minutes,
              CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                   THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                   ELSE NULL
              END AS actual_minutes,
              l.created_at
       FROM leaves l
       LEFT JOIN users u ON u.id=l.employee_id
       LEFT JOIN departments d ON d.id=l.department_id
       ${sqlWhere}
       ORDER BY l.created_at ASC`,
      params
    );

    await logAudit(req,'REPORT_EXPORT','reports',null,{ type, format, filters: { date: date||null, department_id, unregistered, emp_no: emp_no||null, status: statuses||null } });

    if (format === 'csv') {
      const columns = [
        { header:'id', get:x=>x.id },
        { header:'emp_no', get:x=>x.emp_no },
        { header:'full_name', get:x=>x.full_name },
        { header:'department', get:x=>x.department_name },
        { header:'date', get:x=>String(x.date||'').slice(0,10) },
        { header:'planned_out', get:x=>x.planned_out ? String(x.planned_out).slice(0,5) : '' },
        { header:'planned_in', get:x=>x.planned_in ? String(x.planned_in).slice(0,5) : '' },
        { header:'actual_out', get:x=>x.actual_out ? String(x.actual_out).slice(0,5) : '' },
        { header:'actual_in', get:x=>x.actual_in ? String(x.actual_in).slice(0,5) : '' },
        { header:'planned_minutes', get:x=>x.planned_minutes },
        { header:'actual_minutes', get:x=>x.actual_minutes },
        { header:'status', get:x=>x.status },
        { header:'note', get:x=>x.note },
        { header:'is_unregistered', get:x=>x.is_unregistered },
        { header:'created_at', get:x=>x.created_at }
      ];
      const csv = toCSV(r.rows || [], columns);
      const fname = `report_daily_${date || 'today'}.csv`;
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
      return res.send(csv);
    }

    // XLSX
    const wb = new ExcelJS.Workbook();
    wb.creator = 'DSI Leave System';
    wb.created = new Date();

    addMetaSheet(wb, {
      type: 'daily',
      date: date || 'today',
      filters: { department_id: department_id||null, unregistered, emp_no: emp_no||null, status: statuses||null }
    });

    const ws = wb.addWorksheet('Daily');
    ws.columns = [
      { header:'ID', key:'id', width:10 },
      { header:'Emp No', key:'emp_no', width:14 },
      { header:'Name', key:'full_name', width:22 },
      { header:'Department', key:'department_name', width:18 },
      { header:'Date', key:'date', width:12 },
      { header:'Planned OUT', key:'planned_out', width:12 },
      { header:'Planned IN', key:'planned_in', width:12 },
      { header:'Actual OUT', key:'actual_out', width:12 },
      { header:'Actual IN', key:'actual_in', width:12 },
      { header:'Planned Min', key:'planned_minutes', width:12 },
      { header:'Actual Min', key:'actual_minutes', width:12 },
      { header:'Status', key:'status', width:18 },
      { header:'Note', key:'note', width:30 },
      { header:'Unregistered', key:'is_unregistered', width:12 },
      { header:'Created At', key:'created_at', width:22 }
    ];
    styleHeader(ws);

    (r.rows || []).forEach(row=>{
      ws.addRow({
        ...row,
        date: String(row.date||'').slice(0,10),
        planned_out: row.planned_out ? String(row.planned_out).slice(0,5) : '',
        planned_in: row.planned_in ? String(row.planned_in).slice(0,5) : '',
        actual_out: row.actual_out ? String(row.actual_out).slice(0,5) : '',
        actual_in: row.actual_in ? String(row.actual_in).slice(0,5) : ''
      });
    });

    const buf = await wb.xlsx.writeBuffer();
    const fname = `report_daily_${date || 'today'}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.send(Buffer.from(buf));
  }

  // --------
  // MONTHLY / YEARLY (aggregations with multi-sheets)
  // --------
  async function exportMonthly(){
    const year = Number(q.year);
    const month = Number(q.month);
    if(!year || !month) return res.status(400).json({ message:'year and month required' });

    const start = `${year}-${String(month).padStart(2,'0')}-01`;
    const params = [start];
    let i = 2;
    const where = [
      `l.date >= $1::date`,
      `l.date < ($1::date + INTERVAL '1 month')`
    ];
    if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
    if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
    if (emp_no){ where.push(`COALESCE(u.emp_no, l.unregistered_emp_id) ILIKE $${i++}`); params.push(`%${emp_no}%`); }
    if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }
    const sqlWhere = 'WHERE ' + where.join(' AND ');

    const byEmp = await query(
      `SELECT
          COALESCE(u.emp_no, l.unregistered_emp_id, '—') AS emp_no,
          COALESCE(u.full_name, l.unregistered_name, 'Unregistered') AS full_name,
          BOOL_OR(l.is_unregistered) AS is_unregistered,
          COUNT(*)::int AS requests,
          COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
          COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                            THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                            ELSE 0 END),0)::int AS actual_minutes
       FROM leaves l
       LEFT JOIN users u ON u.id=l.employee_id
       ${sqlWhere}
       GROUP BY emp_no, full_name
       ORDER BY planned_minutes DESC, requests DESC
       LIMIT 500`,
      params
    );

    const byDept = await query(
      `SELECT d.id, COALESCE(d.name,'—') AS name,
              COUNT(*)::int AS requests,
              COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
              COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                            THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                            ELSE 0 END),0)::int AS actual_minutes
       FROM leaves l
       LEFT JOIN departments d ON d.id=l.department_id
       LEFT JOIN users u ON u.id=l.employee_id
       ${sqlWhere}
       GROUP BY d.id, name
       ORDER BY planned_minutes DESC, requests DESC`,
      params
    );

    await logAudit(req,'REPORT_EXPORT','reports',null,{ type, format, filters: { year, month, department_id, unregistered, emp_no: emp_no||null, status: statuses||null } });

    const wb = new ExcelJS.Workbook();
    wb.creator = 'DSI Leave System';
    wb.created = new Date();

    addMetaSheet(wb, {
      type: 'monthly',
      year, month,
      filters: { department_id: department_id||null, unregistered, emp_no: emp_no||null, status: statuses||null }
    });

    const wsEmp = wb.addWorksheet('By Employee');
    wsEmp.columns = [
      { header:'Emp No', key:'emp_no', width:14 },
      { header:'Name', key:'full_name', width:24 },
      { header:'Unregistered', key:'is_unregistered', width:12 },
      { header:'Requests', key:'requests', width:12 },
      { header:'Planned Minutes', key:'planned_minutes', width:16 },
      { header:'Actual Minutes', key:'actual_minutes', width:16 }
    ];
    styleHeader(wsEmp);
    (byEmp.rows||[]).forEach(r=>wsEmp.addRow(r));

    const wsDept = wb.addWorksheet('By Department');
    wsDept.columns = [
      { header:'Dept ID', key:'id', width:10 },
      { header:'Department', key:'name', width:22 },
      { header:'Requests', key:'requests', width:12 },
      { header:'Planned Minutes', key:'planned_minutes', width:16 },
      { header:'Actual Minutes', key:'actual_minutes', width:16 }
    ];
    styleHeader(wsDept);
    (byDept.rows||[]).forEach(r=>wsDept.addRow(r));

    const buf = await wb.xlsx.writeBuffer();
    const fname = `report_monthly_${year}-${String(month).padStart(2,'0')}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.send(Buffer.from(buf));
  }

  async function exportYearly(){
    const year = Number(q.year);
    if(!year) return res.status(400).json({ message:'year required' });

    const start = `${year}-01-01`;
    const params = [start];
    let i = 2;
    const where = [
      `l.date >= $1::date`,
      `l.date < ($1::date + INTERVAL '1 year')`
    ];
    if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
    if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
    if (emp_no){ where.push(`COALESCE(u.emp_no, l.unregistered_emp_id) ILIKE $${i++}`); params.push(`%${emp_no}%`); }
    if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }
    const sqlWhere = 'WHERE ' + where.join(' AND ');

    const byEmp = await query(
      `SELECT
          COALESCE(u.emp_no, l.unregistered_emp_id, '—') AS emp_no,
          COALESCE(u.full_name, l.unregistered_name, 'Unregistered') AS full_name,
          BOOL_OR(l.is_unregistered) AS is_unregistered,
          COUNT(*)::int AS requests,
          COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
          COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                            THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                            ELSE 0 END),0)::int AS actual_minutes
       FROM leaves l
       LEFT JOIN users u ON u.id=l.employee_id
       ${sqlWhere}
       GROUP BY emp_no, full_name
       ORDER BY planned_minutes DESC, requests DESC
       LIMIT 2000`,
      params
    );

    const byDept = await query(
      `SELECT d.id, COALESCE(d.name,'—') AS name,
              COUNT(*)::int AS requests,
              COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
              COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                            THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                            ELSE 0 END),0)::int AS actual_minutes
       FROM leaves l
       LEFT JOIN departments d ON d.id=l.department_id
       LEFT JOIN users u ON u.id=l.employee_id
       ${sqlWhere}
       GROUP BY d.id, name
       ORDER BY planned_minutes DESC, requests DESC`,
      params
    );

    await logAudit(req,'REPORT_EXPORT','reports',null,{ type, format, filters: { year, department_id, unregistered, emp_no: emp_no||null, status: statuses||null } });

    const wb = new ExcelJS.Workbook();
    wb.creator = 'DSI Leave System';
    wb.created = new Date();

    addMetaSheet(wb, {
      type: 'yearly',
      year,
      filters: { department_id: department_id||null, unregistered, emp_no: emp_no||null, status: statuses||null }
    });

    const wsEmp = wb.addWorksheet('By Employee');
    wsEmp.columns = [
      { header:'Emp No', key:'emp_no', width:14 },
      { header:'Name', key:'full_name', width:24 },
      { header:'Unregistered', key:'is_unregistered', width:12 },
      { header:'Requests', key:'requests', width:12 },
      { header:'Planned Minutes', key:'planned_minutes', width:16 },
      { header:'Actual Minutes', key:'actual_minutes', width:16 }
    ];
    styleHeader(wsEmp);
    (byEmp.rows||[]).forEach(r=>wsEmp.addRow(r));

    const wsDept = wb.addWorksheet('By Department');
    wsDept.columns = [
      { header:'Dept ID', key:'id', width:10 },
      { header:'Department', key:'name', width:22 },
      { header:'Requests', key:'requests', width:12 },
      { header:'Planned Minutes', key:'planned_minutes', width:16 },
      { header:'Actual Minutes', key:'actual_minutes', width:16 }
    ];
    styleHeader(wsDept);
    (byDept.rows||[]).forEach(r=>wsDept.addRow(r));

    const buf = await wb.xlsx.writeBuffer();
    const fname = `report_yearly_${year}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.send(Buffer.from(buf));
  }

  // --------
  // TRENDS (single sheet)
  // --------
  async function exportTrends(){
    const from = String(q.from||'').trim();
    const to = String(q.to||'').trim();
    const group = String(q.group||'day').toLowerCase();
    if(!from || !to) return res.status(400).json({ message:'from and to required (YYYY-MM-DD)' });
    if(!isISODate(from) || !isISODate(to)) return res.status(400).json({ message:'Invalid from/to date (YYYY-MM-DD)' });

    const bucket = group === 'month' ? "date_trunc('month', l.date)::date" : 'l.date';
    const params = [from, to];
    let i = 3;
    const where = [`l.date >= $1::date`, `l.date <= $2::date`];
    if (department_id){ where.push(`l.department_id = $${i++}`); params.push(department_id); }
    if (unregistered !== null){ where.push(`l.is_unregistered = $${i++}`); params.push(unregistered); }
    if (statuses){ where.push(`l.status = ANY($${i++}::text[])`); params.push(statuses); }
    const sqlWhere = 'WHERE ' + where.join(' AND ');

    const r = await query(
      `SELECT ${bucket} AS bucket,
              COUNT(*)::int AS requests,
              COALESCE(SUM(EXTRACT(EPOCH FROM (l.planned_in - l.planned_out))/60),0)::int AS planned_minutes,
              COALESCE(SUM(CASE WHEN l.actual_out IS NOT NULL AND l.actual_in IS NOT NULL
                            THEN EXTRACT(EPOCH FROM (l.actual_in - l.actual_out))/60
                            ELSE 0 END),0)::int AS actual_minutes
       FROM leaves l
       ${sqlWhere}
       GROUP BY bucket
       ORDER BY bucket ASC`,
      params
    );

    await logAudit(req,'REPORT_EXPORT','reports',null,{ type, format, filters: { from, to, group, department_id, unregistered, status: statuses||null } });

    const wb = new ExcelJS.Workbook();
    wb.creator = 'DSI Leave System';
    wb.created = new Date();

    addMetaSheet(wb, {
      type: 'trends',
      from, to, group,
      filters: { department_id: department_id||null, unregistered, status: statuses||null }
    });

    const ws = wb.addWorksheet('Trends');
    ws.columns = [
      { header:'Bucket', key:'bucket', width:14 },
      { header:'Requests', key:'requests', width:12 },
      { header:'Planned Minutes', key:'planned_minutes', width:16 },
      { header:'Actual Minutes', key:'actual_minutes', width:16 }
    ];
    styleHeader(ws);
    (r.rows||[]).forEach(row=>{
      ws.addRow({
        ...row,
        bucket: String(row.bucket||'').slice(0,10)
      });
    });

    const buf = await wb.xlsx.writeBuffer();
    const fname = `report_trends_${from}_to_${to}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.send(Buffer.from(buf));
  }

  // Dispatch
  if (type === 'daily') return exportDaily();
  if (type === 'monthly') return exportMonthly();
  if (type === 'yearly') return exportYearly();
  return exportTrends();
});
// --------------------
// Audit (ADMIN only)
// --------------------
router.get('/audit', authMiddleware, requireRole('ADMIN'), async (req,res)=>{
  const q = req.query || {};
  const where = [];
  const params = [];
  let i=1;

  if(q.user_id){
    where.push(`user_id=$${i++}`);
    params.push(Number(q.user_id));
  }
  if(q.action){
    where.push(`action ILIKE $${i++}`);
    params.push(`%${q.action}%`);
  }
  if(q.entity){
    where.push(`entity=$${i++}`);
    params.push(String(q.entity));
  }
  if(q.from){
    where.push(`created_at >= $${i++}::timestamp`);
    params.push(String(q.from));
  }
  if(q.to){
    where.push(`created_at <= $${i++}::timestamp`);
    params.push(String(q.to));
  }

  const sqlWhere = where.length ? ('WHERE ' + where.join(' AND ')) : '';
  const r = await query(
    `SELECT id,user_id,role,action,entity,entity_id,ip,user_agent,meta,created_at
     FROM audit_logs
     ${sqlWhere}
     ORDER BY created_at DESC
     LIMIT 400`,
    params
  );
  res.json({ rows: r.rows });
});

// --------------------
// Backups (ADMIN only)
// --------------------
router.get('/admin/backups', authMiddleware, requireRole('ADMIN'), async (req,res)=>{
  const rows = listBackups();
  res.json({ rows });
});

router.post('/admin/backup', authMiddleware, requireRole('ADMIN'), async (req,res)=>{
  const meta = await createBackup();
  await logAudit(req,'BACKUP_CREATE','backup',null,meta);
  res.json({ ok:true, backup: meta });
});

router.post('/admin/restore', authMiddleware, requireRole('ADMIN'), async (req,res)=>{
  const sql_file = String((req.body||{}).sql_file || '').trim();
  if(!sql_file) return res.status(400).json({ message:'sql_file required' });
  await restoreFromSql(sql_file);
  await logAudit(req,'BACKUP_RESTORE','backup',null,{ sql_file });
  res.json({ ok:true });
});


module.exports = router;
