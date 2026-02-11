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
    CREATE INDEX IF NOT EXISTS idx_sessoes_last_update ON sessoes(last_update);
    CREATE INDEX IF NOT EXISTS idx_user_cache_last_update ON user_cache(last_update);
  `);
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

module.exports = {
  getDb,
  getSession,
  setSession,
  updateSessionLastUpdate,
  listSessions,
  getUserData,
  setUserData,
  deleteOldCache,
  DB_PATH
};
