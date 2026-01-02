const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { query } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '2h';

if (!JWT_SECRET) {
  // Fail fast in any environment; you can set a dummy value for local dev in .env
  throw new Error('JWT_SECRET is required (set it in environment variables)');
}


function signToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, department_id: user.department_id },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Enforce ACTIVE accounts (blocks deactivated/locked users)
    const { rows } = await query('SELECT status FROM users WHERE id=$1 LIMIT 1', [payload.id]);
    const status = rows[0]?.status || 'INACTIVE';
    if (String(status).toUpperCase() !== 'ACTIVE') {
      return res.status(401).json({ message: 'Account disabled' });
    }
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}


function requireRole(...roles) {
  return (req, res, next) => {
    const r = (req.user?.role || '').toUpperCase();
    if (!roles.map(x=>x.toUpperCase()).includes(r)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

async function getUserByEmail(email) {
  const { rows } = await query(
    'SELECT id, email, full_name, emp_no, role, department_id, password_hash, status FROM users WHERE email=$1 LIMIT 1',
    [email.toLowerCase()]
  );
  return rows[0] || null;
}

async function getUserById(id) {
  const { rows } = await query(
    'SELECT id, email, full_name, emp_no, role, department_id, status FROM users WHERE id=$1 LIMIT 1',
    [id]
  );
  return rows[0] || null;
}

module.exports = {
  signToken,
  authMiddleware,
  requireRole,
  getUserByEmail,
  getUserById
};
