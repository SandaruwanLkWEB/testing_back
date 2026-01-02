require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();
const routes = require('./routes');
const cron = require('node-cron');
const { createBackup } = require('./backup');

const PORT = process.env.PORT || 8080;

// Behind proxies (Railway/NGINX) this helps rate-limit + IP logging
app.set('trust proxy', 1);

// Basic hardening
app.use(helmet());

// Restrict CORS in production
const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function(origin, cb){
    // allow same-origin / curl / server-to-server
    if (!origin) return cb(null, true);
    if (!allowed.length) {
      // if ALLOWED_ORIGINS not set, default to allow all in non-production
      if ((process.env.NODE_ENV || '').toLowerCase() !== 'production') return cb(null, true);
      return cb(new Error('CORS blocked: set ALLOWED_ORIGINS'), false);
    }
    if (allowed.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'), false);
  },
  credentials: true
}));

// Body limits
app.use(express.json({ limit: process.env.BODY_LIMIT || '1mb' }));

// Rate-limit login (protect brute force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.LOGIN_RATE_LIMIT_MAX || 20),
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/auth/login', loginLimiter);

app.use('/api', routes);

app.get('/', (req,res)=>res.json({ ok:true, message:'Short Leave Backend v9' }));

app.get('/api/health', async (req,res)=>{
  // very lightweight health check
  res.json({ ok:true, ts: new Date().toISOString() });
});

// Central error handler (avoid stack traces in prod)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const isProd = (process.env.NODE_ENV || '').toLowerCase() === 'production';
  const msg = isProd ? 'Server error' : (err.message || 'Server error');
  res.status(500).json({ message: msg });
});

app.listen(PORT, ()=>{
  console.log('Server listening on port', PORT);

  const auto = (process.env.AUTO_BACKUP || 'true').toLowerCase() === 'true';
  if(auto){
    // Daily backup at 02:00 Colombo time
    cron.schedule('0 2 * * *', async ()=>{
      try{ await createBackup(); console.log('[backup] created'); }
      catch(e){ console.warn('[backup] failed', e.message); }
    }, { timezone: 'Asia/Colombo' });
  }
});
