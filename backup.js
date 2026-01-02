const fs = require('fs');
const path = require('path');
const { pool, query } = require('./db');

function backupsDir(){
  const dir = process.env.BACKUP_DIR || path.join(process.cwd(), 'backups');
  if(!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive:true });
  return dir;
}

function tsName(){
  const d = new Date();
  const pad = (n)=>String(n).padStart(2,'0');
  return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function sqlValue(v){
  if(v === null || v === undefined) return 'NULL';
  if(typeof v === 'number') return Number.isFinite(v) ? String(v) : 'NULL';
  if(typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
  if(v instanceof Date) return `'${v.toISOString().replace('T',' ').replace('Z','')}'`;
  // pg returns timestamps as strings by default; treat as string
  const s = String(v).replace(/\\/g,'\\\\').replace(/'/g,"''");
  return `'${s}'`;
}

async function dumpTables(){
  // dump only relevant tables for this app
  const tables = ['departments','users','leaves','notifications','audit_logs'];
  const out = {};
  for(const t of tables){
    const r = await query(`SELECT * FROM ${t} ORDER BY 1 ASC`);
    out[t] = r.rows;
  }
  return out;
}

function generateSqlDump(data){
  const lines = [];
  lines.push('-- Short Leave backup (logical dump)');
  lines.push('BEGIN;');
  lines.push('TRUNCATE TABLE audit_logs RESTART IDENTITY CASCADE;');
  lines.push('TRUNCATE TABLE notifications RESTART IDENTITY CASCADE;');
  lines.push('TRUNCATE TABLE leaves RESTART IDENTITY CASCADE;');
  lines.push('TRUNCATE TABLE users RESTART IDENTITY CASCADE;');
  lines.push('TRUNCATE TABLE departments RESTART IDENTITY CASCADE;');

  const order = ['departments','users','leaves','notifications','audit_logs'];
  for(const t of order){
    const rows = data[t] || [];
    if(rows.length === 0) continue;
    const cols = Object.keys(rows[0]);
    for(const row of rows){
      const vals = cols.map(c=>sqlValue(row[c]));
      lines.push(`INSERT INTO ${t}(${cols.join(',')}) VALUES(${vals.join(',')});`);
    }
  }
  lines.push('COMMIT;');
  return lines.join('\n') + '\n';
}

async function createBackup(){
  const dir = backupsDir();
  const name = `backup-${tsName()}`;
  const jsonPath = path.join(dir, `${name}.json`);
  const sqlPath  = path.join(dir, `${name}.sql`);

  const data = await dumpTables();
  fs.writeFileSync(jsonPath, JSON.stringify({ created_at: new Date().toISOString(), data }, null, 2), 'utf-8');
  fs.writeFileSync(sqlPath, generateSqlDump(data), 'utf-8');

  return { name, json: path.basename(jsonPath), sql: path.basename(sqlPath) };
}

function listBackups(){
  const dir = backupsDir();
  const files = fs.readdirSync(dir).filter(f=>f.startsWith('backup-') && (f.endsWith('.json') || f.endsWith('.sql')));
  // group by name
  const map = new Map();
  for(const f of files){
    const base = f.replace(/\.json$|\.sql$/,'');
    const it = map.get(base) || { name: base, json: null, sql: null };
    if(f.endsWith('.json')) it.json = f;
    if(f.endsWith('.sql')) it.sql = f;
    map.set(base, it);
  }
  return Array.from(map.values()).sort((a,b)=> (a.name < b.name ? 1 : -1));
}

async function restoreFromSql(filename){
  const dir = backupsDir();
  const fpath = path.join(dir, filename);
  if(!fs.existsSync(fpath)) throw new Error('Backup file not found');
  const sql = fs.readFileSync(fpath,'utf-8');

  // Execute our own generated SQL safely: split on ";\n"
  const statements = sql.split(/;\s*\n/).map(s=>s.trim()).filter(Boolean).map(s=>s+';');

  const client = await pool.connect();
  try{
    for(const st of statements){
      // skip comments
      if(st.startsWith('--')) continue;
      await client.query(st);
    }
  } finally {
    client.release();
  }
  return { ok:true };
}

module.exports = { createBackup, listBackups, restoreFromSql };
