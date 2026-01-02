const nodemailer = require('nodemailer');
const { query } = require('./db');

let transporter = null;

function getTransporter(){
  if(transporter) return transporter;
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if(!host || !user || !pass){
    return null;
  }

  transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });
  return transporter;
}

async function sendEmail(to, subject, text){
  const t = getTransporter();
  if(!t){
    // not configured; don't fail the request
    console.log('[email skipped]', { to, subject });
    return { skipped:true };
  }
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  await t.sendMail({ from, to, subject, text });
  return { ok:true };
}

async function createNotification(userId, title, body=null, link=null, meta=null){
  const r = await query(
    `INSERT INTO notifications(user_id,title,body,link,meta) VALUES($1,$2,$3,$4,$5) RETURNING id`,
    [userId, title, body, link, meta]
  );
  return r.rows[0]?.id;
}

async function notifyUsers(userIds, payload){
  const uniq = Array.from(new Set((userIds||[]).filter(Boolean)));
  for(const uid of uniq){
    await createNotification(uid, payload.title, payload.body, payload.link, payload.meta);
  }
}

async function notifyRole(role, payload, department_id=null){
  const params = [];
  let where = "WHERE UPPER(role)=UPPER($1) AND status='ACTIVE'";
  params.push(role);
  if(department_id){
    where += " AND department_id=$2";
    params.push(department_id);
  }
  const r = await query(`SELECT id,email,full_name FROM users ${where}`, params);
  const ids = r.rows.map(x=>x.id);
  await notifyUsers(ids, payload);

  // email (best-effort)
  if(process.env.NOTIFY_EMAILS === 'true'){
    for(const u of r.rows){
      if(u.email){
        await sendEmail(u.email, payload.title, payload.body || payload.title);
      }
    }
  }
  return ids.length;
}

module.exports = { sendEmail, createNotification, notifyUsers, notifyRole };
