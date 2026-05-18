// PostgreSQL pool + tiny query helper.
// On boot, applies schema.sql if needed (idempotent — uses CREATE TABLE IF NOT EXISTS).
import pg from 'pg';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { Pool } = pg;

// Render's Postgres connection string is provided via DATABASE_URL.
// ssl is required when connecting from outside Render's network and harmless inside it.
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false },
  max: 10
});

pool.on('error', (err) => {
  console.error('[db] unexpected pool error:', err);
});

// q(text, params) — thin wrapper that returns rows directly
export async function q(text, params = []) {
  const res = await pool.query(text, params);
  return res.rows;
}

export async function one(text, params = []) {
  const rows = await q(text, params);
  return rows[0] || null;
}

// Apply schema.sql on boot. Safe to call repeatedly.
export async function ensureSchema() {
  const sql = readFileSync(join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(sql);
  console.log('[db] schema ensured');
}
