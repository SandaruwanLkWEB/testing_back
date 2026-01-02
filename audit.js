const { query } = require('./db');

async function logAudit(req, action, entity=null, entity_id=null, meta=null){
  try{
    const user_id = req.user?.id || null;
    const role = req.user?.role || null;
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim();
    const ua = (req.headers['user-agent'] || '').toString().slice(0,400);
    await query(
      `INSERT INTO audit_logs(user_id,role,action,entity,entity_id,ip,user_agent,meta)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [user_id, role, action, entity, entity_id, ip, ua, meta]
    );
  }catch(e){
    console.warn('audit log failed', e.message);
  }
}

module.exports = { logAudit };
