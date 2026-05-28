// HailGrade backend — single-file Express app.
// Endpoints:
//   POST   /auth/signup     — create user
//   POST   /auth/login      — get JWT
//   GET    /me              — current user info
//   POST   /analyze         — proxy a roof photo to Claude, log usage
//   POST   /billing/checkout — create Stripe Checkout session
//   POST   /billing/portal   — open Stripe billing portal
//   POST   /webhooks/stripe  — Stripe webhook receiver
//   GET    /health          — liveness probe for Render

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import Stripe from 'stripe';
import { pool, q, one, ensureSchema } from './db.js';
import { hashPassword, checkPassword, signToken, requireAuth, requireActiveSubscription } from './auth.js';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

// Trim whitespace from every env var on boot — Render's UI can leave hidden newlines
// in pasted secrets, which breaks Stripe webhook signature verification etc.
for (const k of Object.keys(process.env)) {
  if (typeof process.env[k] === 'string') {
    process.env[k] = process.env[k].trim();
  }
}

const app = express();
const port = process.env.PORT || 3000;

// CORS — allow the HailGrade frontend (hailgrade.com) and local dev.
const ALLOWED_ORIGINS = [
  'https://hailgrade.com',
  'https://www.hailgrade.com',
  'https://ampleclaim.com',
  'https://www.ampleclaim.com',
  'https://helpful-gecko-1923b8.netlify.app',
  'http://localhost:5173',
  'http://localhost:8080'
];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // Allow any *.netlify.app subdomain in case of preview deploys
    if (/\.netlify\.app$/.test(new URL(origin).hostname)) return cb(null, true);
    cb(new Error('CORS not allowed for ' + origin));
  }
}));

// Stripe webhook needs the raw body, so register it BEFORE express.json()
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), handleStripeWebhook);

// All other routes use JSON
app.use(express.json({ limit: '60mb' })); // 25mb so phone-quality JPEGs fit

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

// ============ Health ============
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, version: '0.1.0', db: 'up' });
  } catch (err) {
    res.status(500).json({ ok: false, db: 'down', error: err.message });
  }
});

// ============ Auth ============
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password, full_name, license_number, firm_name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email_and_password_required' });
    if (password.length < 8) return res.status(400).json({ error: 'password_too_short', message: 'Password must be at least 8 characters.' });
    const lower = email.trim().toLowerCase();
    const existing = await one('SELECT id FROM users WHERE lower(email) = $1', [lower]);
    if (existing) return res.status(409).json({ error: 'email_in_use' });
    const hash = await hashPassword(password);
    const user = await one(
      `INSERT INTO users (email, password_hash, full_name, license_number, firm_name)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, full_name, license_number, firm_name, role, plan, plan_status`,
      [lower, hash, full_name || null, license_number || null, firm_name || null]
    );
    const token = signToken(user);
    res.json({ token, user });
  } catch (err) {
    console.error('[signup]', err);
    res.status(500).json({ error: 'signup_failed', detail: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email_and_password_required' });
    const lower = email.trim().toLowerCase();
    const user = await one('SELECT * FROM users WHERE lower(email) = $1', [lower]);
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    const ok = await checkPassword(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
    const token = signToken(user);
    res.json({
      token,
      user: { id: user.id, email: user.email, full_name: user.full_name, license_number: user.license_number, firm_name: user.firm_name, role: user.role, plan: user.plan, plan_status: user.plan_status }
    });
  } catch (err) {
    console.error('[login]', err);
    res.status(500).json({ error: 'login_failed' });
  }
});

// Founder emails — auto-promoted to admin on any authenticated request.
// Add additional admin emails here if you bring on a co-founder or support staff.
const ADMIN_EMAILS = new Set(['adjustingsmith@gmail.com', 'claims@smithadjusters.com']);

app.get('/me', requireAuth, async (req, res) => {
  const u = req.user;
  // Auto-promote founder emails to admin so they don't need a SQL session to bootstrap
  if (ADMIN_EMAILS.has((u.email || '').toLowerCase()) && u.role !== 'admin') {
    await q("UPDATE users SET role = 'admin' WHERE id = $1", [u.id]);
    u.role = 'admin';
  }
  res.json({
    user: {
      id: u.id, email: u.email, full_name: u.full_name, license_number: u.license_number,
      firm_name: u.firm_name, role: u.role, plan: u.plan, plan_status: u.plan_status,
      plan_renews_at: u.plan_renews_at,
      monthly_analyses_used: u.monthly_analyses_used,
      org_id: u.org_id, org_role: u.org_role, active: u.active
    }
  });
});

// ============ Admin middleware ============
// Admin endpoints require BOTH an admin-role user (auth token) AND a separate admin password
// passed in X-Admin-Password header. The password is set as ADMIN_PASSWORD env var on Render.
// This is intentional belt-and-suspenders: even if someone steals an admin's auth token,
// they still can't view or mutate other accounts without the password.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin_only' });
  }
  const provided = req.headers['x-admin-password'];
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) {
    // No password configured on the server — soft-fail open with a warning header so
    // admin can still set things up the first time (the env var is the lock, missing == no lock).
    res.setHeader('X-Admin-Warning', 'ADMIN_PASSWORD not set on server — anyone with admin role can use this');
    return next();
  }
  if (provided !== expected) {
    return res.status(401).json({ error: 'admin_password_required' });
  }
  next();
}

// Lightweight endpoint to verify the admin password before loading the dashboard.
// Returns 200 if (a) user is admin and (b) password matches, else 401/403.
app.get('/admin/verify', requireAuth, requireAdmin, (req, res) => {
  res.json({ ok: true, configured: !!process.env.ADMIN_PASSWORD });
});

// ============ Admin endpoints ============
// Aggregate stats for the admin dashboard.
app.get('/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const [users] = await q(`SELECT
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE plan_status IN ('active','trialing'))::int AS paying,
      COUNT(*) FILTER (WHERE plan_status = 'past_due')::int AS past_due,
      COUNT(*) FILTER (WHERE plan_status = 'canceled')::int AS canceled,
      COUNT(*) FILTER (WHERE created_at > now() - interval '7 days')::int AS new_this_week
      FROM users`);
    const [analyses] = await q(`SELECT
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE created_at > now() - interval '30 days')::int AS month,
      COUNT(*) FILTER (WHERE created_at > now() - interval '7 days')::int AS week,
      COUNT(*) FILTER (WHERE created_at > now() - interval '24 hours')::int AS day,
      COUNT(*) FILTER (WHERE status = 'error')::int AS errors,
      COUNT(*) FILTER (WHERE is_roof = false)::int AS not_roof,
      COALESCE(SUM(cost_cents), 0)::int AS total_cost_cents,
      COALESCE(SUM(cost_cents) FILTER (WHERE created_at > now() - interval '30 days'), 0)::int AS month_cost_cents
      FROM analyses`);
    const findings = await q(`SELECT category, COUNT(*)::int AS n
      FROM findings WHERE created_at > now() - interval '30 days'
      GROUP BY category ORDER BY n DESC`);
    // Rough MRR: $49 * solo + $149 * firm (active or trialing only)
    const planCounts = await q(`SELECT plan, COUNT(*)::int AS n FROM users
      WHERE plan_status IN ('active','trialing') AND plan IS NOT NULL
      GROUP BY plan`);
    let mrrCents = 0;
    for (const r of planCounts) {
      if (r.plan === 'solo') mrrCents += r.n * 4900;
      else if (r.plan === 'firm') mrrCents += r.n * 14900;
    }
    res.json({ users, analyses, findings, plans: planCounts, mrr_cents: mrrCents });
  } catch (err) {
    console.error('[admin/stats]', err);
    res.status(500).json({ error: 'stats_failed', detail: err.message });
  }
});

// List users with pagination + search
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  const search = (req.query.search || '').trim().toLowerCase();
  try {
    let rows;
    if (search) {
      rows = await q(
        `SELECT id, email, full_name, license_number, firm_name, role, plan, plan_status,
                plan_renews_at, monthly_analyses_used, created_at, stripe_customer_id
         FROM users
         WHERE lower(email) LIKE $1 OR lower(coalesce(full_name,'')) LIKE $1 OR lower(coalesce(firm_name,'')) LIKE $1
         ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
        ['%' + search + '%', limit, offset]
      );
    } else {
      rows = await q(
        `SELECT id, email, full_name, license_number, firm_name, role, plan, plan_status,
                plan_renews_at, monthly_analyses_used, created_at, stripe_customer_id
         FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
        [limit, offset]
      );
    }
    // Attach analysis count per user (cheap on small data; revisit when scale grows)
    const [totalRow] = await q(`SELECT COUNT(*)::int AS n FROM users`);
    res.json({ users: rows, total: totalRow.n, limit, offset });
  } catch (err) {
    console.error('[admin/users]', err);
    res.status(500).json({ error: 'list_failed', detail: err.message });
  }
});

// Update a user (role, plan_status, license, firm, name)
app.patch('/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'bad_id' });
  const allowed = ['role', 'plan_status', 'plan', 'license_number', 'firm_name', 'full_name'];
  const fields = Object.keys(req.body || {}).filter(k => allowed.includes(k));
  if (fields.length === 0) return res.status(400).json({ error: 'no_updatable_fields' });
  const sets = fields.map((k, i) => `${k} = $${i + 2}`).join(', ');
  const values = fields.map(k => req.body[k]);
  try {
    const updated = await one(
      `UPDATE users SET ${sets} WHERE id = $1 RETURNING id, email, full_name, role, plan, plan_status`,
      [id, ...values]
    );
    if (!updated) return res.status(404).json({ error: 'not_found' });
    res.json({ user: updated });
  } catch (err) {
    console.error('[admin/users PATCH]', err);
    res.status(500).json({ error: 'update_failed', detail: err.message });
  }
});

// Delete a user (cascades to analyses and findings via FK)
app.delete('/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'bad_id' });
  if (id === req.user.id) return res.status(400).json({ error: 'cannot_delete_self' });
  try {
    await q('DELETE FROM users WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[admin/users DELETE]', err);
    res.status(500).json({ error: 'delete_failed', detail: err.message });
  }
});

// Recent analyses across all users
app.get('/admin/analyses', requireAuth, requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  try {
    const rows = await q(
      `SELECT a.id, a.slope, a.is_roof, a.overall_severity, a.roof_material,
              a.damage_categories, a.findings_count, a.cost_cents, a.status, a.created_at,
              u.email AS user_email
       FROM analyses a JOIN users u ON u.id = a.user_id
       ORDER BY a.created_at DESC LIMIT $1`,
      [limit]
    );
    res.json({ analyses: rows });
  } catch (err) {
    console.error('[admin/analyses]', err);
    res.status(500).json({ error: 'list_failed', detail: err.message });
  }
});

// ============ Organizations (master / enterprise accounts) ============
// An org has one owner and any number of members. The owner generates invite
// codes; members join with a code. The owner gets a team activity dashboard,
// can deactivate accounts, and can transfer a departed member's workflow to a
// newly hired account.

function makeInviteCode() {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous chars
  let s = '';
  for (let i = 0; i < 7; i++) s += abc[Math.floor(Math.random() * abc.length)];
  return 'HG-' + s;
}

async function loadOrgContext(userId) {
  const u = await one('SELECT id, org_id, org_role FROM users WHERE id = $1', [userId]);
  if (!u || !u.org_id) return { org: null, role: null };
  const org = await one('SELECT id, name, owner_user_id, created_at FROM orgs WHERE id = $1', [u.org_id]);
  if (!org) return { org: null, role: null };
  return { org, role: u.org_role || 'member' };
}

async function templateOwnerIdFor(user) {
  if (user && user.org_id && user.org_role === 'member') {
    try {
      const r = await one('SELECT owner_user_id FROM orgs WHERE id = $1', [user.org_id]);
      if (r && r.owner_user_id) return r.owner_user_id;
    } catch (e) {}
  }
  return user.id;
}

// GET /org — current user's org state. Owners also get members (with stats) + invites.
app.get('/org', requireAuth, async (req, res) => {
  try {
    const ctx = await loadOrgContext(req.user.id);
    if (!ctx.org) return res.json({ org: null, role: null });
    const out = { org: { id: ctx.org.id, name: ctx.org.name, created_at: ctx.org.created_at }, role: ctx.role };
    if (ctx.role === 'owner') {
      out.members = await q(
        `SELECT u.id, u.email, u.full_name, u.org_role, u.active, u.created_at,
                (SELECT COUNT(*) FROM analyses a WHERE a.user_id = u.id)::int AS analyses,
                (SELECT COUNT(*) FROM contracts c WHERE c.user_id = u.id)::int AS contracts_sent,
                (SELECT COUNT(*) FROM contracts c WHERE c.user_id = u.id AND c.status IN ('signed','complete','completed'))::int AS contracts_signed,
                (SELECT COUNT(*) FROM leads l WHERE l.assigned_to = u.id)::int AS leads_assigned,
                (SELECT COUNT(*) FROM leads l WHERE l.assigned_to = u.id AND l.status = 'converted')::int AS leads_converted,
                GREATEST(
                  COALESCE((SELECT MAX(created_at) FROM analyses a WHERE a.user_id = u.id), 'epoch'),
                  COALESCE((SELECT MAX(created_at) FROM contracts c WHERE c.user_id = u.id), 'epoch')
                ) AS last_activity
         FROM users u WHERE u.org_id = $1
         ORDER BY (u.org_role = 'owner') DESC, u.created_at ASC`,
        [ctx.org.id]
      );
      out.invites = await q(
        `SELECT id, code, label, email, created_at, used_by, used_at, revoked
         FROM org_invites WHERE org_id = $1 ORDER BY created_at DESC`,
        [ctx.org.id]
      );
    }
    res.json(out);
  } catch (err) {
    console.error('[org GET]', err);
    res.status(500).json({ error: 'org_failed', detail: err.message });
  }
});

// POST /org/create — caller becomes the owner of a new org.
app.post('/org/create', requireAuth, async (req, res) => {
  try {
    const name = ((req.body && req.body.name) || '').trim();
    if (!name) return res.status(400).json({ error: 'name_required' });
    const me = await one('SELECT org_id FROM users WHERE id = $1', [req.user.id]);
    if (me && me.org_id) return res.status(409).json({ error: 'already_in_org' });
    const org = await one(
      'INSERT INTO orgs (name, owner_user_id) VALUES ($1, $2) RETURNING id, name, created_at',
      [name, req.user.id]
    );
    await q("UPDATE users SET org_id = $1, org_role = 'owner' WHERE id = $2", [org.id, req.user.id]);
    res.json({ ok: true, org });
  } catch (err) {
    console.error('[org/create]', err);
    res.status(500).json({ error: 'create_failed', detail: err.message });
  }
});

// POST /org/invite — owner generates a join code.
app.post('/org/invite', requireAuth, async (req, res) => {
  try {
    const ctx = await loadOrgContext(req.user.id);
    if (!ctx.org || ctx.role !== 'owner') return res.status(403).json({ error: 'owner_only' });
    const label = (((req.body && req.body.label) || '').trim()) || null;
    const email = (((req.body && req.body.email) || '').trim().toLowerCase()) || null;
    let inserted = null;
    for (let attempt = 0; attempt < 6 && !inserted; attempt++) {
      try {
        inserted = await one(
          'INSERT INTO org_invites (org_id, code, label, email, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING id, code, label, email, created_at, used_by, used_at, revoked',
          [ctx.org.id, makeInviteCode(), label, email, req.user.id]
        );
      } catch (e) { inserted = null; }
    }
    if (!inserted) return res.status(500).json({ error: 'code_generation_failed' });
    res.json({ ok: true, invite: inserted });
  } catch (err) {
    console.error('[org/invite]', err);
    res.status(500).json({ error: 'invite_failed', detail: err.message });
  }
});

// POST /org/invite/:id/revoke — owner revokes a code.
app.post('/org/invite/:id/revoke', requireAuth, async (req, res) => {
  try {
    const ctx = await loadOrgContext(req.user.id);
    if (!ctx.org || ctx.role !== 'owner') return res.status(403).json({ error: 'owner_only' });
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    await q('UPDATE org_invites SET revoked = true WHERE id = $1 AND org_id = $2', [id, ctx.org.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[org/invite revoke]', err);
    res.status(500).json({ error: 'revoke_failed', detail: err.message });
  }
});

// POST /org/join — member joins via invite code.
app.post('/org/join', requireAuth, async (req, res) => {
  try {
    const raw = (((req.body && req.body.code) || '').trim()).toUpperCase();
    if (!raw) return res.status(400).json({ error: 'code_required' });
    const me = await one('SELECT org_id FROM users WHERE id = $1', [req.user.id]);
    if (me && me.org_id) return res.status(409).json({ error: 'already_in_org' });
    const invite = await one('SELECT * FROM org_invites WHERE upper(code) = $1', [raw]);
    if (!invite) return res.status(404).json({ error: 'invalid_code' });
    if (invite.revoked) return res.status(410).json({ error: 'code_revoked' });
    if (invite.used_by) return res.status(410).json({ error: 'code_used' });
    const org = await one('SELECT id, name FROM orgs WHERE id = $1', [invite.org_id]);
    if (!org) return res.status(404).json({ error: 'org_not_found' });
    await q("UPDATE users SET org_id = $1, org_role = 'member' WHERE id = $2", [org.id, req.user.id]);
    await q('UPDATE org_invites SET used_by = $1, used_at = now() WHERE id = $2', [req.user.id, invite.id]);
    res.json({ ok: true, org });
  } catch (err) {
    console.error('[org/join]', err);
    res.status(500).json({ error: 'join_failed', detail: err.message });
  }
});

// POST /org/member/:id/deactivate — owner disables a member account.
app.post('/org/member/:id/deactivate', requireAuth, async (req, res) => {
  try {
    const ctx = await loadOrgContext(req.user.id);
    if (!ctx.org || ctx.role !== 'owner') return res.status(403).json({ error: 'owner_only' });
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    if (id === req.user.id) return res.status(400).json({ error: 'cannot_deactivate_self' });
    const target = await one('SELECT id, org_id FROM users WHERE id = $1', [id]);
    if (!target || target.org_id !== ctx.org.id) return res.status(404).json({ error: 'not_in_org' });
    await q('UPDATE users SET active = false WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[org/member deactivate]', err);
    res.status(500).json({ error: 'deactivate_failed', detail: err.message });
  }
});

// POST /org/member/:id/reactivate — owner re-enables a member account.
app.post('/org/member/:id/reactivate', requireAuth, async (req, res) => {
  try {
    const ctx = await loadOrgContext(req.user.id);
    if (!ctx.org || ctx.role !== 'owner') return res.status(403).json({ error: 'owner_only' });
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    const target = await one('SELECT id, org_id FROM users WHERE id = $1', [id]);
    if (!target || target.org_id !== ctx.org.id) return res.status(404).json({ error: 'not_in_org' });
    await q('UPDATE users SET active = true WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[org/member reactivate]', err);
    res.status(500).json({ error: 'reactivate_failed', detail: err.message });
  }
});

// POST /org/transfer — move a departed member's workflow to a new hire.
app.post('/org/transfer', requireAuth, async (req, res) => {
  try {
    const ctx = await loadOrgContext(req.user.id);
    if (!ctx.org || ctx.role !== 'owner') return res.status(403).json({ error: 'owner_only' });
    const fromId = parseInt(req.body && req.body.from_user_id);
    const toId = parseInt(req.body && req.body.to_user_id);
    const deactivateSource = !!(req.body && req.body.deactivate_source);
    if (!fromId || !toId) return res.status(400).json({ error: 'from_and_to_required' });
    if (fromId === toId) return res.status(400).json({ error: 'same_account' });
    const from = await one('SELECT id, org_id FROM users WHERE id = $1', [fromId]);
    const to = await one('SELECT id, org_id FROM users WHERE id = $1', [toId]);
    if (!from || from.org_id !== ctx.org.id) return res.status(404).json({ error: 'from_not_in_org' });
    if (!to || to.org_id !== ctx.org.id) return res.status(404).json({ error: 'to_not_in_org' });
    const moved = {};
    for (const table of ['analyses', 'findings', 'contracts', 'user_contracts', 'cloud_jobs']) {
      try {
        const rows = await q('UPDATE ' + table + ' SET user_id = $1 WHERE user_id = $2 RETURNING id', [toId, fromId]);
        moved[table] = rows.length;
      } catch (e) { moved[table] = 'skipped'; }
    }
    if (deactivateSource && fromId !== req.user.id) {
      await q('UPDATE users SET active = false WHERE id = $1', [fromId]);
      moved.source_deactivated = true;
    }
    res.json({ ok: true, moved });
  } catch (err) {
    console.error('[org/transfer]', err);
    res.status(500).json({ error: 'transfer_failed', detail: err.message });
  }
});
// ============ Events / scheduling ============
// Each user has a list of events. Org owner can also see all team events,
// assign events to members, and edit/delete them.

// GET /events  - list events. Filters: ?start=ISO&end=ISO&claim=local_id&member=user_id|all (owner only)
app.get('/events', requireAuth, async (req, res) => {
  try {
    const now = Date.now();
    const start = req.query.start || new Date(now - 7 * 86400000).toISOString();
    const end = req.query.end || new Date(now + 120 * 86400000).toISOString();
    const claimId = req.query.claim || null;
    let rows;
    if (req.user.org_id && req.user.org_role === 'owner') {
      const memberFilter = req.query.member;
      if (memberFilter && memberFilter !== 'all') {
        const tgt = parseInt(memberFilter);
        rows = await q('SELECT e.*, u.full_name AS user_name, u.email AS user_email FROM events e JOIN users u ON u.id = e.user_id WHERE e.user_id = $1 AND e.starts_at >= $2 AND e.starts_at <= $3 ORDER BY e.starts_at ASC', [tgt, start, end]);
      } else if (claimId) {
        rows = await q('SELECT e.*, u.full_name AS user_name, u.email AS user_email FROM events e JOIN users u ON u.id = e.user_id WHERE u.org_id = $1 AND e.claim_local_id = $2 ORDER BY e.starts_at ASC', [req.user.org_id, claimId]);
      } else {
        rows = await q('SELECT e.*, u.full_name AS user_name, u.email AS user_email FROM events e JOIN users u ON u.id = e.user_id WHERE u.org_id = $1 AND e.starts_at >= $2 AND e.starts_at <= $3 ORDER BY e.starts_at ASC', [req.user.org_id, start, end]);
      }
    } else {
      if (claimId) {
        rows = await q('SELECT * FROM events WHERE user_id = $1 AND claim_local_id = $2 ORDER BY starts_at ASC', [req.user.id, claimId]);
      } else {
        rows = await q('SELECT * FROM events WHERE user_id = $1 AND starts_at >= $2 AND starts_at <= $3 ORDER BY starts_at ASC', [req.user.id, start, end]);
      }
    }
    res.json({ events: rows });
  } catch (err) {
    console.error('[events GET]', err);
    res.status(500).json({ error: 'list_failed', detail: err.message });
  }
});

app.post('/events', requireAuth, async (req, res) => {
  try {
    const b = req.body || {};
    const title = ((b.title || '') + '').trim();
    if (!title) return res.status(400).json({ error: 'title_required' });
    if (!b.starts_at) return res.status(400).json({ error: 'starts_at_required' });
    let userId = req.user.id;
    if (b.assigned_to && req.user.org_id && req.user.org_role === 'owner') {
      const tgt = parseInt(b.assigned_to);
      if (tgt) {
        const m = await one('SELECT id, org_id FROM users WHERE id = $1', [tgt]);
        if (m && m.org_id === req.user.org_id) userId = tgt;
      }
    }
    const ev = await one(
      'INSERT INTO events (user_id, org_id, claim_local_id, title, description, starts_at, ends_at, all_day, location) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [userId, req.user.org_id || null, b.claim_local_id || null, title, b.description || null, b.starts_at, b.ends_at || null, !!b.all_day, b.location || null]
    );
    res.json({ ok: true, event: ev });
  } catch (err) {
    console.error('[events POST]', err);
    res.status(500).json({ error: 'create_failed', detail: err.message });
  }
});

app.patch('/events/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    const ev = await one('SELECT * FROM events WHERE id = $1', [id]);
    if (!ev) return res.status(404).json({ error: 'not_found' });
    const isMine = ev.user_id === req.user.id;
    const isMyTeam = ev.org_id && req.user.org_id === ev.org_id && req.user.org_role === 'owner';
    if (!isMine && !isMyTeam) return res.status(403).json({ error: 'forbidden' });
    const b = req.body || {};
    const allowed = ['title', 'description', 'starts_at', 'ends_at', 'all_day', 'location', 'claim_local_id'];
    const fields = Object.keys(b).filter(k => allowed.includes(k));
    if (isMyTeam && b.assigned_to) {
      const tgt = parseInt(b.assigned_to);
      if (tgt) {
        const m = await one('SELECT id, org_id FROM users WHERE id = $1', [tgt]);
        if (m && m.org_id === req.user.org_id) {
          fields.push('user_id');
          b.user_id = tgt;
        }
      }
    }
    if (fields.length === 0) return res.status(400).json({ error: 'no_updatable_fields' });
    const sets = fields.map(function(k, i) { return k + ' = ' + ('$' + (i + 2)); }).join(', ') + ', updated_at = now()';
    const vals = fields.map(k => b[k]);
    const updated = await one('UPDATE events SET ' + sets + ' WHERE id = $1 RETURNING *', [id, ...vals]);
    res.json({ ok: true, event: updated });
  } catch (err) {
    console.error('[events PATCH]', err);
    res.status(500).json({ error: 'update_failed', detail: err.message });
  }
});

app.delete('/events/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    const ev = await one('SELECT * FROM events WHERE id = $1', [id]);
    if (!ev) return res.json({ ok: true });
    const isMine = ev.user_id === req.user.id;
    const isMyTeam = ev.org_id && req.user.org_id === ev.org_id && req.user.org_role === 'owner';
    if (!isMine && !isMyTeam) return res.status(403).json({ error: 'forbidden' });
    await q('DELETE FROM events WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[events DELETE]', err);
    res.status(500).json({ error: 'delete_failed', detail: err.message });
  }
});

// ============ Leads (sales pipeline) ============

// GET /leads  - list leads. Owner sees all org leads; member sees own assigned; solo sees self-created.
// Filters: ?status=new|assigned|contacted|converted|lost  ?assigned=user_id|me|unassigned|all
app.get('/leads', requireAuth, async (req, res) => {
  try {
    const isOwner = req.user.org_id && req.user.org_role === 'owner';
    const wh = []; const params = []; let pn = 1;
    if (req.user.org_id) {
      wh.push('l.org_id = ' + ('$' + (pn++)));
      params.push(req.user.org_id);
      if (!isOwner) {
        wh.push('l.assigned_to = ' + ('$' + (pn++)));
        params.push(req.user.id);
      } else {
        const a = req.query.assigned;
        if (a === 'unassigned') wh.push('l.assigned_to IS NULL');
        else if (a === 'me') { wh.push('l.assigned_to = ' + ('$' + (pn++))); params.push(req.user.id); }
        else if (a && a !== 'all') { wh.push('l.assigned_to = ' + ('$' + (pn++))); params.push(parseInt(a)); }
      }
    } else {
      wh.push('l.created_by = ' + ('$' + (pn++)));
      params.push(req.user.id);
    }
    if (req.query.status) { wh.push('l.status = ' + ('$' + (pn++))); params.push(req.query.status); }
    const sql = 'SELECT l.*, u.full_name AS assignee_name, u.email AS assignee_email FROM leads l LEFT JOIN users u ON u.id = l.assigned_to WHERE ' + wh.join(' AND ') + ' ORDER BY l.created_at DESC LIMIT 200';
    const rows = await q(sql, params);
    res.json({ leads: rows });
  } catch (err) {
    console.error('[leads GET]', err);
    res.status(500).json({ error: 'list_failed', detail: err.message });
  }
});

// POST /leads  - create a lead. Owner can pre-assign by passing assigned_to.
app.post('/leads', requireAuth, async (req, res) => {
  try {
    const b = req.body || {};
    const name = ((b.name || '') + '').trim();
    if (!name) return res.status(400).json({ error: 'name_required' });
    const orgId = req.user.org_id || null;
    let assignedTo = null, assignedAt = null, assignedBy = null;
    const isOwner = orgId && req.user.org_role === 'owner';
    if (b.assigned_to && isOwner) {
      const tgt = parseInt(b.assigned_to);
      if (tgt) {
        const m = await one('SELECT id, org_id FROM users WHERE id = ' + '$1', [tgt]);
        if (m && m.org_id === orgId) { assignedTo = tgt; assignedAt = new Date().toISOString(); assignedBy = req.user.id; }
      }
    } else if (!orgId) {
      // Solo user: auto-assign to self
      assignedTo = req.user.id; assignedAt = new Date().toISOString(); assignedBy = req.user.id;
    }
    const status = assignedTo ? 'assigned' : 'new';
    const lead = await one(
      'INSERT INTO leads (org_id, name, email, phone, address, carrier, claim_number, source, notes, assigned_to, assigned_at, assigned_by, status, created_by) VALUES (' + '$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *',
      [orgId, name, b.email || null, b.phone || null, b.address || null, b.carrier || null, b.claim_number || null, b.source || null, b.notes || null, assignedTo, assignedAt, assignedBy, status, req.user.id]
    );
    res.json({ ok: true, lead });
  } catch (err) {
    console.error('[leads POST]', err);
    res.status(500).json({ error: 'create_failed', detail: err.message });
  }
});

// PATCH /leads/:id  - update fields, status, or (owner only) reassign.
app.patch('/leads/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    const lead = await one('SELECT * FROM leads WHERE id = ' + '$1', [id]);
    if (!lead) return res.status(404).json({ error: 'not_found' });
    const isOwner = req.user.org_id && req.user.org_role === 'owner';
    const sameOrg = lead.org_id && lead.org_id === req.user.org_id;
    const isMyLead = lead.assigned_to === req.user.id || lead.created_by === req.user.id;
    if (!(isOwner && sameOrg) && !isMyLead) return res.status(403).json({ error: 'forbidden' });
    const b = req.body || {};
    const allowed = ['name', 'email', 'phone', 'address', 'carrier', 'claim_number', 'source', 'notes', 'status'];
    const fields = Object.keys(b).filter(k => allowed.includes(k));
    if (isOwner && sameOrg && Object.prototype.hasOwnProperty.call(b, 'assigned_to')) {
      const tgt = b.assigned_to ? parseInt(b.assigned_to) : null;
      if (tgt) {
        const m = await one('SELECT id, org_id FROM users WHERE id = ' + '$1', [tgt]);
        if (m && m.org_id === req.user.org_id) {
          fields.push('assigned_to', 'assigned_at', 'assigned_by');
          b.assigned_to = tgt; b.assigned_at = new Date().toISOString(); b.assigned_by = req.user.id;
          if (!('status' in b) || !b.status) { fields.push('status'); b.status = 'assigned'; }
        }
      } else {
        fields.push('assigned_to', 'assigned_at', 'assigned_by');
        b.assigned_to = null; b.assigned_at = null; b.assigned_by = null;
      }
    }
    if (fields.length === 0) return res.status(400).json({ error: 'no_updatable_fields' });
    const sets = fields.map((k, i) => k + ' = ' + ('$' + (i + 2))).join(', ') + ', updated_at = now()';
    const vals = fields.map(k => b[k]);
    const updated = await one('UPDATE leads SET ' + sets + ' WHERE id = ' + '$1' + ' RETURNING *', [id, ...vals]);
    res.json({ ok: true, lead: updated });
  } catch (err) {
    console.error('[leads PATCH]', err);
    res.status(500).json({ error: 'update_failed', detail: err.message });
  }
});

// POST /leads/:id/convert  - mark lead as converted, optionally link to a local job id.
app.post('/leads/:id/convert', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    const lead = await one('SELECT * FROM leads WHERE id = ' + '$1', [id]);
    if (!lead) return res.status(404).json({ error: 'not_found' });
    const isOwner = req.user.org_id && req.user.org_role === 'owner';
    const sameOrg = lead.org_id && lead.org_id === req.user.org_id;
    const isMyLead = lead.assigned_to === req.user.id || lead.created_by === req.user.id;
    if (!(isOwner && sameOrg) && !isMyLead) return res.status(403).json({ error: 'forbidden' });
    const claimLocalId = (req.body && req.body.claim_local_id) || null;
    await q('UPDATE leads SET status = ' + "'converted'" + ', converted_claim_local_id = ' + '$1' + ', converted_at = now(), converted_by = ' + '$2' + ', updated_at = now() WHERE id = ' + '$3',
      [claimLocalId, req.user.id, id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[leads convert]', err);
    res.status(500).json({ error: 'convert_failed', detail: err.message });
  }
});

// DELETE /leads/:id
app.delete('/leads/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'bad_id' });
    const lead = await one('SELECT * FROM leads WHERE id = ' + '$1', [id]);
    if (!lead) return res.json({ ok: true });
    const isOwner = req.user.org_id && req.user.org_role === 'owner';
    const sameOrg = lead.org_id && lead.org_id === req.user.org_id;
    const isMine = lead.created_by === req.user.id;
    if (!(isOwner && sameOrg) && !isMine) return res.status(403).json({ error: 'forbidden' });
    await q('DELETE FROM leads WHERE id = ' + '$1', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[leads DELETE]', err);
    res.status(500).json({ error: 'delete_failed', detail: err.message });
  }
});

// ============ ClaimWizard webhook (Zapier-driven) ============
// One-way sync from ClaimWizard into Ample as new Leads.
// Setup: in Zapier, create a Zap with ClaimWizard "New Client Added" trigger,
// then Action = Webhooks by Zapier (POST) to this URL with the client fields.
// Auth: a shared secret in the URL path. Set ZAPIER_WEBHOOK_SECRET on Render.
// Owner mapping: leads are created under the user whose email matches
// ZAPIER_USER_EMAIL (defaults to claims@smithadjusters.com).
const ZAPIER_WEBHOOK_SECRET = (process.env.ZAPIER_WEBHOOK_SECRET || '').trim();
const ZAPIER_USER_EMAIL = (process.env.ZAPIER_USER_EMAIL || 'claims@smithadjusters.com').trim().toLowerCase();

app.post('/webhooks/zapier/claimwizard/:secret', async (req, res) => {
  try {
    if (!ZAPIER_WEBHOOK_SECRET) {
      return res.status(503).json({ error: 'webhook not configured' });
    }
    if (req.params.secret !== ZAPIER_WEBHOOK_SECRET) {
      return res.status(401).json({ error: 'invalid secret' });
    }

    // Owner lookup — by configured email so we don't need a per-user token yet
    const ur = await pool.query(
      "SELECT id, org_id FROM users WHERE LOWER(email) = $1 LIMIT 1",
      [ZAPIER_USER_EMAIL]
    );
    if (!ur.rowCount) return res.status(500).json({ error: 'configured user not found' });
    const userId = ur.rows[0].id;
    const orgId = ur.rows[0].org_id || null;

    // Field mapping — Zapier lets the user map ClaimWizard fields to whatever
    // keys they want, so we accept many common variants for each field.
    const b = req.body || {};
    const pickStr = (...keys) => {
      for (const k of keys) {
        const v = b[k];
        if (v !== undefined && v !== null && String(v).trim() !== '') {
          return String(v).trim();
        }
      }
      return '';
    };
    const composedName = (function() {
      const f = pickStr('first_name', 'firstName', 'first');
      const l = pickStr('last_name', 'lastName', 'last');
      return (f || l) ? (f + (f && l ? ' ' : '') + l) : '';
    })();
    const name = (pickStr('name', 'client_name', 'full_name', 'fullName', 'policyholder', 'policy_holder') || composedName || 'Synced client').slice(0, 200);
    const email = (pickStr('email', 'client_email', 'policyholder_email', 'primary_email') || null);
    const phone = (pickStr('phone', 'phone_number', 'phoneNumber', 'mobile', 'cell', 'primary_phone') || null);
    const addressLine = pickStr('address', 'address1', 'street', 'street_address', 'property_address');
    const city = pickStr('city', 'property_city');
    const state = pickStr('state', 'property_state', 'region');
    const zip = pickStr('zip', 'zip_code', 'zipcode', 'postal_code', 'postcode');
    const fullAddress = [addressLine, city, state, zip].filter(Boolean).join(', ') || null;
    const carrier = pickStr('carrier', 'insurance_company', 'insurer', 'company') || null;
    const claimNumber = pickStr('claim_number', 'claim_no', 'claimNumber', 'claim_id') || null;
    const notesIn = pickStr('notes', 'note', 'description', 'remarks') || null;

    const ins = await pool.query(
      `INSERT INTO leads (org_id, assigned_to, name, email, phone, address, carrier, claim_number, source, status, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'new', $10) RETURNING id`,
      [orgId, userId, name, email, phone, fullAddress, carrier, claimNumber, 'ClaimWizard sync', notesIn]
    );

    return res.status(201).json({ ok: true, lead_id: ins.rows[0].id, name });
  } catch (err) {
    console.error('[zapier:claimwizard]', err);
    return res.status(500).json({ error: String((err && err.message) || err).slice(0, 200) });
  }
});

// Health/ping for Zapier setup - the user can use this to verify the URL works
// without actually creating a lead.
app.get('/webhooks/zapier/claimwizard/:secret/ping', (req, res) => {
  if (!ZAPIER_WEBHOOK_SECRET) return res.status(503).json({ ok: false, error: 'webhook not configured' });
  if (req.params.secret !== ZAPIER_WEBHOOK_SECRET) return res.status(401).json({ ok: false, error: 'invalid secret' });
  return res.json({ ok: true, message: 'Webhook URL is valid', at: new Date().toISOString() });
});


// ============ Team jobs (master account aggregated pipeline) ============
// Each member's device auto-syncs a denormalized snapshot of their local jobs.
// Owner reads the aggregated view to see where every deal sits.

// POST /team-jobs  - bulk upsert of the caller's jobs (silently skipped for solo users).
app.post('/team-jobs', requireAuth, async (req, res) => {
  try {
    if (!req.user.org_id) return res.json({ ok: true, skipped: 'solo_user' });
    const jobs = (req.body && req.body.jobs) || [];
    if (!Array.isArray(jobs)) return res.status(400).json({ error: 'jobs_must_be_array' });
    let upserted = 0;
    for (const j of jobs) {
      if (!j || !j.claim_local_id) continue;
      try {
        await q(
          'INSERT INTO team_jobs (user_id, org_id, claim_local_id, name, address, insured, insured_email, carrier, claim_number, stage, has_damage, contract_status, finalized, photos_count, last_touched) VALUES ' + '($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT (user_id, claim_local_id) DO UPDATE SET name = EXCLUDED.name, address = EXCLUDED.address, insured = EXCLUDED.insured, insured_email = EXCLUDED.insured_email, carrier = EXCLUDED.carrier, claim_number = EXCLUDED.claim_number, stage = EXCLUDED.stage, has_damage = EXCLUDED.has_damage, contract_status = EXCLUDED.contract_status, finalized = EXCLUDED.finalized, photos_count = EXCLUDED.photos_count, last_touched = EXCLUDED.last_touched, updated_at = now()',
          [req.user.id, req.user.org_id, String(j.claim_local_id), j.name || null, j.address || null, j.insured || null, j.insured_email || null, j.carrier || null, j.claim_number || null, j.stage || null, !!j.has_damage, j.contract_status || null, !!j.finalized, parseInt(j.photos_count) || 0, j.last_touched || new Date().toISOString()]
        );
        upserted++;
      } catch (e) { console.error('[team-jobs upsert]', e.message); }
    }
    res.json({ ok: true, upserted });
  } catch (err) {
    console.error('[team-jobs POST]', err);
    res.status(500).json({ error: 'sync_failed', detail: err.message });
  }
});

// GET /team-jobs  - owner-only. Returns every member's jobs in the org.
app.get('/team-jobs', requireAuth, async (req, res) => {
  try {
    if (!req.user.org_id || req.user.org_role !== 'owner') {
      return res.status(403).json({ error: 'owner_only' });
    }
    const rows = await q(
      'SELECT t.*, u.full_name AS member_name, u.email AS member_email FROM team_jobs t JOIN users u ON u.id = t.user_id WHERE u.org_id = ' + '$1' + ' ORDER BY t.last_touched DESC NULLS LAST, t.updated_at DESC LIMIT 1000',
      [req.user.org_id]
    );
    res.json({ jobs: rows });
  } catch (err) {
    console.error('[team-jobs GET]', err);
    res.status(500).json({ error: 'list_failed', detail: err.message });
  }
});

// DELETE /team-jobs/:claimId  - member-initiated cleanup when a local job is removed.
app.delete('/team-jobs/:claimId', requireAuth, async (req, res) => {
  try {
    const cl = req.params.claimId;
    if (!cl) return res.status(400).json({ error: 'bad_id' });
    await q('DELETE FROM team_jobs WHERE user_id = ' + '$1' + ' AND claim_local_id = ' + '$2', [req.user.id, cl]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[team-jobs DELETE]', err);
    res.status(500).json({ error: 'delete_failed', detail: err.message });
  }
});

app.patch('/me', requireAuth, async (req, res) => {
  const { full_name, license_number, firm_name } = req.body || {};
  await q(
    `UPDATE users SET full_name = $1, license_number = $2, firm_name = $3 WHERE id = $4`,
    [full_name || null, license_number || null, firm_name || null, req.user.id]
  );
  res.json({ ok: true });
});

// ============ Anthropic proxy ============
// Body: { image: base64-encoded JPEG/PNG, media_type, slope, context: {dateOfLoss, carrier, testSquare}}
// Response: the parsed JSON from Claude, plus a server-side analysis_id you can store on the client.
app.post('/analyze', requireAuth, requireActiveSubscription, async (req, res) => {
  const { image, image_enhanced, media_type, slope, context = {}, photo_local_id, claim_local_id } = req.body || {};
  if (!image || !media_type) return res.status(400).json({ error: 'image_required' });

  // Soft monthly quota check (avoid runaway costs from a single user)
  const u = req.user;
  const quota = u.plan === 'firm' ? 2500 : 600;  // generous; tighten later
  if (u.monthly_analyses_used >= quota) {
    return res.status(429).json({ error: 'quota_exceeded', message: `Monthly quota of ${quota} analyses hit. Resets on ${u.monthly_analyses_reset_at}.` });
  }

  let prompt = buildAnalysisPrompt({ slope, ...context });
  if (image_enhanced) {
    prompt = "IMPORTANT: You are given TWO images that are the SAME single roof photo. The first is the original. The second is a contrast-enhanced copy of that same photo (local-contrast boosted) that makes subtle hail bruising, dents and granule loss easier to see. Treat them as ONE photo, not two. Use the enhanced copy as an aid to spot subtle damage and to confirm or rule out marginal findings, but judge real severity from the original. Do NOT double-count: an impact visible in both copies is ONE finding. The enhancement can exaggerate texture and shadow, so do not report damage that is only an artifact of the enhancement and absent in the original.\n\n" + prompt;
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 3500,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type, data: image }},
            ...(image_enhanced ? [{ type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: image_enhanced }}] : []),
            { type: 'text', text: prompt }
          ]
        }]
      })
    });

    const data = await response.json();
    if (!response.ok) {
      console.error('[analyze] anthropic returned', response.status, data);
      return res.status(502).json({ error: 'upstream_error', status: response.status, detail: data });
    }

    const text = (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('').trim();
    const cleaned = text.replace(/^```json\s*|\s*```$/g, '').trim();
    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (e) {
      console.error('[analyze] failed to parse model output:', cleaned.slice(0, 500));
      return res.status(502).json({ error: 'bad_model_output', raw: cleaned });
    }

    // Cost calc: Claude Sonnet 4.6 input ~$3/Mtok, output ~$15/Mtok (approx — update as needed)
    const usage = data.usage || {};
    const costCents = Math.ceil(
      ((usage.input_tokens || 0) * 0.0003 + (usage.output_tokens || 0) * 0.0015)
    );

    // Log to database
    const analysis = await one(
      `INSERT INTO analyses
       (user_id, claim_local_id, photo_local_id, slope, gps_lat, gps_lng, date_of_loss, carrier,
        is_roof, overall_severity, roof_material, damage_categories, findings_count,
        prompt_tokens, output_tokens, cost_cents, raw_response, model, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
       RETURNING id`,
      [
        u.id, claim_local_id || null, photo_local_id || null, slope || null,
        context.gps?.lat || null, context.gps?.lng || null,
        context.dateOfLoss || null, context.carrier || null,
        parsed.is_roof !== false, parsed.overall_severity || null, parsed.roof_material || null,
        parsed.damage_categories_present || [], (parsed.findings || []).length,
        usage.input_tokens || null, usage.output_tokens || null, costCents,
        parsed, 'claude-sonnet-4-6',
        parsed.is_roof === false ? 'not_roof' : 'ok'
      ]
    );

    // Log each finding
    for (const f of (parsed.findings || [])) {
      await q(
        `INSERT INTO findings (analysis_id, user_id, finding_local_id, category, cause_origin,
          severity, type, description, bbox_x, bbox_y, bbox_w, bbox_h)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          analysis.id, u.id, f.id || null, f.category || null, f.cause_origin || null,
          f.severity || null, f.type || null, f.description || null,
          f.bbox?.x || null, f.bbox?.y || null, f.bbox?.w || null, f.bbox?.h || null
        ]
      );
    }

    // Increment monthly usage counter
    await q('UPDATE users SET monthly_analyses_used = monthly_analyses_used + 1 WHERE id = $1', [u.id]);

    res.json({ ok: true, analysis_id: analysis.id, result: parsed, cost_cents: costCents });
  } catch (err) {
    console.error('[analyze]', err);
    res.status(500).json({ error: 'analyze_failed', detail: err.message });
  }
});

// ============ Stripe billing ============
app.post('/billing/checkout', requireAuth, async (req, res) => {
  try {
    const { plan = 'solo' } = req.body || {};
    const priceId = plan === 'firm' ? process.env.STRIPE_PRICE_FIRM : process.env.STRIPE_PRICE_SOLO;
    if (!priceId) return res.status(500).json({ error: 'price_not_configured' });

    // Get or create Stripe customer
    let customerId = req.user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        name: req.user.full_name || undefined,
        metadata: { user_id: req.user.id.toString() }
      });
      customerId = customer.id;
      await q('UPDATE users SET stripe_customer_id = $1 WHERE id = $2', [customerId, req.user.id]);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: (process.env.FRONTEND_URL || 'https://hailgrade.com') + '/?subscribed=1',
      cancel_url: (process.env.FRONTEND_URL || 'https://hailgrade.com') + '/?canceled=1',
      allow_promotion_codes: true
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[checkout]', err);
    res.status(500).json({ error: 'checkout_failed', detail: err.message });
  }
});

app.post('/billing/portal', requireAuth, async (req, res) => {
  try {
    if (!req.user.stripe_customer_id) return res.status(400).json({ error: 'no_customer' });
    const session = await stripe.billingPortal.sessions.create({
      customer: req.user.stripe_customer_id,
      return_url: process.env.FRONTEND_URL || 'https://hailgrade.com'
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('[portal]', err);
    res.status(500).json({ error: 'portal_failed', detail: err.message });
  }
});

// ============ Weather history ============
// Pulls hail / high-wind events near a property from the past N days.
// Sources:
//   - Open-Meteo Historical (wind gusts) — free, no API key
//   - Iowa State Mesonet (NWS Local Storm Reports for hail) — free, no API key
// Geocoding: Nominatim (OSM) — free, requires User-Agent header
app.post('/weather/history', requireAuth, async (req, res) => {
  try {
    let { address, lat, lng, days } = req.body || {};
    days = Math.min(Math.max(parseInt(days, 10) || 365, 7), 730);

    // 1. Geocode the address when no GPS coords were supplied
    let geocoded = null;
    if ((!lat || !lng) && address) {
      const gu = 'https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=us&q=' + encodeURIComponent(address);
      const gr = await fetch(gu, { headers: { 'User-Agent': 'HailGrade/1.0 (claims@smithadjusters.com)' } });
      if (gr.ok) {
        const arr = await gr.json();
        if (arr.length) { lat = parseFloat(arr[0].lat); lng = parseFloat(arr[0].lon); geocoded = { display: arr[0].display_name }; }
      }
    }
    if (!lat || !lng) return res.status(400).json({ error: 'no_location', detail: 'Could not geocode the address and no GPS was provided.' });
    lat = parseFloat(lat); lng = parseFloat(lng);

    // 2. Find the NWS forecast office (WFO) covering this point
    let wfo = null, placeCity = null, placeState = null;
    try {
      const pr = await fetch('https://api.weather.gov/points/' + lat.toFixed(4) + ',' + lng.toFixed(4), {
        headers: { 'User-Agent': 'HailGrade/1.0 (claims@smithadjusters.com)', 'Accept': 'application/geo+json' }
      });
      if (pr.ok) {
        const pd = await pr.json();
        wfo = pd.properties && pd.properties.cwa;
        const rl = pd.properties && pd.properties.relativeLocation && pd.properties.relativeLocation.properties;
        if (rl) { placeCity = rl.city; placeState = rl.state; }
      }
    } catch (e) { console.error('[weather] NWS points failed', e.message); }
    if (!wfo) return res.status(502).json({ error: 'no_office', detail: 'Could not determine the NWS forecast office for this location.' });

    // 3. Pull NWS Local Storm Reports for that office over the time window
    const end = new Date();
    const start = new Date(end.getTime() - days * 86400 * 1000);
    const sts = start.toISOString().slice(0, 16) + 'Z';
    const ets = end.toISOString().slice(0, 16) + 'Z';
    const lsrUrl = 'https://mesonet.agron.iastate.edu/cgi-bin/request/gis/lsr.py?sts=' + sts + '&ets=' + ets + '&wfo=' + wfo + '&fmt=csv';
    let csv = '';
    try {
      const lr = await fetch(lsrUrl);
      if (lr.ok) csv = await lr.text();
    } catch (e) { console.error('[weather] LSR fetch failed', e.message); }

    // 4. Parse the CSV into hail + wind events within ~25 miles of the property.
    // Columns: VALID,VALID2,LAT,LON,MAG,WFO,TYPECODE,TYPETEXT,CITY,COUNTY,STATE,SOURCE,REMARK,UGC,UGCNAME,QUALIFIER
    const hailEvents = [], windEvents = [];
    const lines = csv.split(/\r?\n/);
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const c = line.split(',');
      if (c.length < 13) continue;
      const elat = parseFloat(c[2]), elng = parseFloat(c[3]);
      if (!isFinite(elat) || !isFinite(elng)) continue;
      const typetext = (c[7] || '').toUpperCase();
      const isHail = typetext.indexOf('HAIL') !== -1;
      const isWind = typetext.indexOf('WND') !== -1 || typetext.indexOf('WIND') !== -1;
      if (!isHail && !isWind) continue;
      const dist = haversineMi(lat, lng, elat, elng);
      if (dist > 25) continue;
      const v = c[0] || '';
      const date = v.length >= 8 ? (v.slice(0,4) + '-' + v.slice(4,6) + '-' + v.slice(6,8)) : '';
      const mag = parseFloat(c[4]);
      const remark = c.slice(12, Math.max(13, c.length - 3)).join(',').trim();
      const ev = {
        date: date,
        type: isHail ? 'hail' : 'wind',
        magnitude: (isFinite(mag) && mag > 0) ? mag : null,
        unit: isHail ? 'in' : 'mph',
        type_text: c[7] || '',
        distance_mi: Math.round(dist * 10) / 10,
        city: c[8] || '',
        county: c[9] || '',
        remark: remark.slice(0, 180),
        source: 'NWS Local Storm Report'
      };
      if (isHail) hailEvents.push(ev); else windEvents.push(ev);
    }

    const events = hailEvents.concat(windEvents)
      .sort((x, y) => {
        if (x.date !== y.date) return (y.date || '').localeCompare(x.date || '');
        return x.distance_mi - y.distance_mi;
      })
      .slice(0, 120);

    res.json({
      ok: true,
      location: { lat: lat, lng: lng, wfo: wfo, city: placeCity, state: placeState, geocoded: geocoded },
      window: { start: start.toISOString().slice(0,10), end: end.toISOString().slice(0,10), days: days },
      counts: { hail: hailEvents.length, wind: windEvents.length, total: hailEvents.length + windEvents.length },
      events: events
    });
  } catch (err) {
    console.error('[weather/history]', err);
    res.status(500).json({ error: 'weather_failed', detail: err.message });
  }
});

/* ===================== CONTRACTS / E-SIGNATURE ===================== */
const DS_API_KEY = process.env.DROPBOX_SIGN_API_KEY || "";
const DS_BASE = "https://api.hellosign.com/v3";
let _contractsSchemaReady = false;
async function ensureContractsSchema() {
  if (_contractsSchemaReady) return;
  await q("CREATE TABLE IF NOT EXISTS user_contracts (user_id INTEGER PRIMARY KEY, filename TEXT, pdf_base64 TEXT, uploaded_at TIMESTAMPTZ DEFAULT now())");
  await q("CREATE TABLE IF NOT EXISTS contracts (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, claim_local_id TEXT, claim_name TEXT, signer_name TEXT, signer_email TEXT, signature_request_id TEXT, status TEXT DEFAULT 'sent', signed_pdf_url TEXT, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())");
  try { await q("ALTER TABLE contracts ADD COLUMN IF NOT EXISTS price TEXT"); } catch (e) {}
  try { await q("ALTER TABLE user_contracts ADD COLUMN IF NOT EXISTS field_map TEXT"); } catch (e) {}
  try { await q("ALTER TABLE user_contracts ADD COLUMN IF NOT EXISTS doc_json TEXT"); } catch (e) {}
  try { await q("ALTER TABLE user_contracts DROP CONSTRAINT IF EXISTS user_contracts_pkey"); } catch (e) {}
  try { await q("ALTER TABLE user_contracts ADD COLUMN IF NOT EXISTS id SERIAL PRIMARY KEY"); } catch (e) {}
  try { await q("ALTER TABLE user_contracts ADD COLUMN IF NOT EXISTS name TEXT"); } catch (e) {}
  _contractsSchemaReady = true;
}
function dsAuthHeader() {
  return "Basic " + Buffer.from(DS_API_KEY + ":").toString("base64");
}
function dsRowsOf(r) { return Array.isArray(r) ? r : (r && r.rows ? r.rows : []); }

app.post("/contracts/template", requireAuth, async (req, res) => {
  if (req.user && req.user.org_id && req.user.org_role === 'member') return res.status(403).json({ error: 'member_cannot_edit_templates', message: 'Your team owner manages contract templates.' });
  try {
    await ensureContractsSchema();
    const body = req.body || {};
    if (!body.pdf_base64) return res.status(400).json({ error: "Missing contract file" });
    const clean = String(body.pdf_base64).replace(/^data:[^,]*,/, "");
    const fn = body.filename || "contract.pdf";
    await q("INSERT INTO user_contracts (user_id, name, filename, pdf_base64, uploaded_at) VALUES ($1,$2,$3,$4, now())", [req.user.id, ((body.name || "").trim() || fn), fn, clean]);
    res.json({ ok: true, filename: fn });
  } catch (e) {
    console.error("[contracts/template]", e);
    res.status(500).json({ error: "Could not save contract" });
  }
});

app.get("/contracts/template", requireAuth, async (req, res) => {
  try { req.user.id = await templateOwnerIdFor(req.user); } catch (e) {}
  try {
    await ensureContractsSchema();
    const rows = dsRowsOf(await q("SELECT filename, uploaded_at FROM user_contracts WHERE user_id=$1 ORDER BY id DESC LIMIT 1", [req.user.id]));
    if (!rows.length) return res.json({ hasTemplate: false });
    res.json({ hasTemplate: true, filename: rows[0].filename, uploaded_at: rows[0].uploaded_at });
  } catch (e) {
    console.error("[contracts/template:get]", e);
    res.status(500).json({ error: "Could not load contract" });
  }
});

app.post("/contracts/send", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    if (!DS_API_KEY) return res.status(500).json({ error: "E-signature is not configured" });
    const body = req.body || {};
    const signerName = (body.signer_name || "").trim();
    const signerEmail = (body.signer_email || "").trim();
    if (!signerName || !signerEmail) return res.status(400).json({ error: "Client name and email are required" });
    const tpl = dsRowsOf(await q("SELECT id, filename, pdf_base64, field_map, doc_json FROM user_contracts WHERE user_id=$1 AND id = COALESCE($2::int, (SELECT MAX(id) FROM user_contracts WHERE user_id=$1))", [await templateOwnerIdFor(req.user), ((req.body && req.body.contract_id) ? parseInt(req.body.contract_id, 10) : null)]));
    if (!tpl.length) return res.status(400).json({ error: "Upload your contract first" });
    const pdfBuf = Buffer.from(tpl[0].pdf_base64, "base64");
    let docJson = null;
    try { docJson = tpl[0].doc_json ? JSON.parse(tpl[0].doc_json) : null; } catch (e) { docJson = null; }
    let fieldMap = [];
    try { fieldMap = tpl[0].field_map ? JSON.parse(tpl[0].field_map) : []; } catch (e) { fieldMap = []; }
    let _hasClient2 = false, _needsAdjuster = false;
    try {
      (docJson && Array.isArray(docJson.sections) ? docJson.sections : []).forEach(function (sx) {
        if (!sx) return;
        var _isS = sx.kind === "signature" || (sx.kind === "field" && (sx.field_id === "signature" || sx.field_id === "initials" || sx.field_id === "date_signed"));
        if (!_isS) return;
        if (sx.signer === "client2") _hasClient2 = true;
        if (sx.signer === "adjuster") _needsAdjuster = true;
      });
    } catch (e) {}
    var _signer2Name = String(body.signer2_name || "").trim();
    var _signer2Email = String(body.signer2_email || "").trim();
    var _useClient2 = _hasClient2 && !!_signer2Email;
    var signerMap = { client: "signer1", client2: "signer1", adjuster: "signer1" };
    var _mpos = 1;
    if (_useClient2) { signerMap.client2 = "signer" + (_mpos + 1); _mpos++; }
    if (_needsAdjuster) { signerMap.adjuster = "signer" + (_mpos + 1); _mpos++; }
    let mergedBuf;
    try {
      if (docJson && Array.isArray(docJson.sections) && docJson.sections.length) { mergedBuf = await renderContractPdf(docJson, { mode: "filled", body: body, user: req.user, signer_map: signerMap }); }
      else if (Array.isArray(fieldMap) && fieldMap.length) { mergedBuf = await fillContractPdf(pdfBuf, fieldMap, body, req.user); }
      else { mergedBuf = await buildAgreementPdf(pdfBuf, body, req.user); }
    }
    catch (e) { console.error("[contracts/send] merge", e); return res.status(500).json({ error: "Could not build the agreement PDF. Try re-uploading your contract." }); }
    const form = new FormData();
    const claimName = body.claim_name || "";
    form.append("title", "Roofing Agreement" + (claimName ? " - " + claimName : ""));
    form.append("subject", "Please sign your roofing agreement");
    form.append("message", "Please review and sign your roofing agreement. A signed copy will be emailed to all parties once complete.");
    form.append("signers[0][name]", signerName);
    form.append("signers[0][email_address]", signerEmail);
    form.append("signers[0][order]", "0");
    let _sp = 1;
    if (_useClient2) {
      form.append("signers[" + _sp + "][name]", _signer2Name || "Second Signer");
      form.append("signers[" + _sp + "][email_address]", _signer2Email);
      form.append("signers[" + _sp + "][order]", String(_sp));
      _sp++;
    }
    if (_needsAdjuster) {
      form.append("signers[" + _sp + "][name]", req.user.full_name || req.user.firm_name || "Public Adjuster");
      form.append("signers[" + _sp + "][email_address]", req.user.email);
      form.append("signers[" + _sp + "][order]", String(_sp));
      _sp++;
    } else {
      form.append("cc_email_addresses[0]", req.user.email);
    }
    form.append("test_mode", "1");
    form.append("use_text_tags", "1");
    form.append("hide_text_tags", "1");
    form.append("file[0]", new Blob([mergedBuf], { type: "application/pdf" }), "roofing-agreement.pdf");
    const dsRes = await fetch(DS_BASE + "/signature_request/send", { method: "POST", headers: { "Authorization": dsAuthHeader() }, body: form });
    const dsJson = await dsRes.json().catch(() => ({}));
    if (!dsRes.ok) {
      console.error("[contracts/send] provider error", dsRes.status, JSON.stringify(dsJson));
      const msg = (dsJson && dsJson.error && dsJson.error.error_msg) || "E-signature provider rejected the request";
      return res.status(502).json({ error: msg });
    }
    const sr = dsJson.signature_request || {};
    const srId = sr.signature_request_id || "";
    const ins = dsRowsOf(await q("INSERT INTO contracts (user_id, claim_local_id, claim_name, signer_name, signer_email, signature_request_id, status, price) VALUES ($1,$2,$3,$4,$5,$6,'sent',$7) RETURNING id", [req.user.id, body.claim_local_id || null, claimName || null, signerName, signerEmail, srId, body.price || null]));
    res.json({ ok: true, id: ins[0] ? ins[0].id : null, signature_request_id: srId, status: "sent" });
  } catch (e) {
    console.error("[contracts/send]", e);
    res.status(500).json({ error: "Could not send contract" });
  }
});

app.get("/contracts/list", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    const cid = req.query.claim_local_id;
    let rows;
    if (cid) {
      rows = dsRowsOf(await q("SELECT id, claim_local_id, claim_name, signer_name, signer_email, signature_request_id, status, signed_pdf_url, created_at, updated_at FROM contracts WHERE user_id=$1 AND claim_local_id=$2 ORDER BY created_at DESC", [req.user.id, cid]));
    } else {
      rows = dsRowsOf(await q("SELECT id, claim_local_id, claim_name, signer_name, signer_email, signature_request_id, status, signed_pdf_url, created_at, updated_at FROM contracts WHERE user_id=$1 ORDER BY created_at DESC", [req.user.id]));
    }
    res.json({ contracts: rows });
  } catch (e) {
    console.error("[contracts/list]", e);
    res.status(500).json({ error: "Could not load contracts" });
  }
});

app.get("/contracts/status/:id", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    const rows = dsRowsOf(await q("SELECT id, signature_request_id, status FROM contracts WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]));
    if (!rows.length) return res.status(404).json({ error: "Contract not found" });
    const row = rows[0];
    if (!row.signature_request_id || !DS_API_KEY) return res.json({ status: row.status });
    const dsRes = await fetch(DS_BASE + "/signature_request/" + encodeURIComponent(row.signature_request_id), { headers: { "Authorization": dsAuthHeader() } });
    const dsJson = await dsRes.json().catch(() => ({}));
    if (!dsRes.ok) return res.json({ status: row.status });
    const sr = dsJson.signature_request || {};
    const sigs = sr.signatures || [];
    let status = "sent";
    if (sr.is_complete) status = "signed";
    else if (sigs.some(function(s){ return s.status_code === "declined"; })) status = "declined";
    const signedUrl = sr.files_url || null;
    await q("UPDATE contracts SET status=$1, signed_pdf_url=COALESCE($2, signed_pdf_url), updated_at=now() WHERE id=$3", [status, signedUrl, row.id]);
    res.json({ status: status, signed_pdf_url: signedUrl, is_complete: !!sr.is_complete });
  } catch (e) {
    console.error("[contracts/status]", e);
    res.status(500).json({ error: "Could not refresh status" });
  }
});
app.get("/contracts/template/file", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    const rows = dsRowsOf(await q("SELECT id, name, filename, pdf_base64, uploaded_at, field_map, doc_json FROM user_contracts WHERE user_id=$1 AND id = COALESCE($2::int, (SELECT MAX(id) FROM user_contracts WHERE user_id=$1))", [await templateOwnerIdFor(req.user), (req.query.id ? parseInt(req.query.id, 10) : null)]));
    if (!rows.length) return res.status(404).json({ error: "No contract on file" });
    let _fm = null; try { _fm = rows[0].field_map ? JSON.parse(rows[0].field_map) : null; } catch (e) { _fm = null; }
    let _doc = null; try { _doc = rows[0].doc_json ? JSON.parse(rows[0].doc_json) : null; } catch (e) { _doc = null; }
    let outputPdf = rows[0].pdf_base64;
    if (_doc && Array.isArray(_doc.sections) && _doc.sections.length) {
      try { const buf = await renderContractPdf(_doc, { mode: "blank" }); outputPdf = Buffer.from(buf).toString("base64"); }
      catch (e) { console.warn("[contracts/template/file] render fallback:", e.message); }
    }
    res.json({ id: rows[0].id, name: rows[0].name || "", filename: rows[0].filename, pdf_base64: outputPdf, original_pdf_base64: rows[0].pdf_base64, uploaded_at: rows[0].uploaded_at, field_map: _fm, doc: _doc });
  } catch (e) {
    console.error("[contracts/template/file]", e);
    res.status(500).json({ error: "Could not load contract file" });
  }
});

app.post("/contracts/template/fieldmap", requireAuth, async (req, res) => {
  if (req.user && req.user.org_id && req.user.org_role === 'member') return res.status(403).json({ error: 'member_cannot_edit_templates', message: 'Your team owner manages contract templates.' });
  try {
    await ensureContractsSchema();
    const fm = (req.body && req.body.field_map) || [];
    if (!Array.isArray(fm)) return res.status(400).json({ error: "field_map must be an array" });
    await q("UPDATE user_contracts SET field_map=$1 WHERE user_id=$2", [JSON.stringify(fm), req.user.id]);
    res.json({ ok: true, count: fm.length });
  } catch (e) {
    console.error("[contracts/fieldmap:save]", e);
    res.status(500).json({ error: "Could not save the field layout" });
  }
});

const DETECT_FIELDS_PROMPT = `You are looking at page images of a roofing contract. Find every BLANK FILL-IN FIELD that a person would write into: an empty underline, a blank space after a printed label, or an empty box. For each blank, give its position as a fraction of the page from 0 to 1, where x and y are the TOP-LEFT corner measured from the top-left of the page, and w and h are the width and height of the blank. Classify each blank as one of these types by reading the printed label next to it: client_name, property_address, phone, email, carrier, claim_number, price, scope, agreement_date, signature, date_signed, other. Use signature for where the customer signs their name. Use date_signed for the date blank right beside that customer signature. Use agreement_date for a contract date or agreement date near the top of the document. Use price for any contract price, total, amount, or dollar figure blank. Be precise with coordinates so the box sits directly on the blank. Return ONLY a JSON array and nothing else, in exactly this shape: [{"type":"client_name","page":1,"x":0.35,"y":0.21,"w":0.4,"h":0.03}]. The page value is 1-based. If you find no blanks, return [].`;

app.post("/contracts/detect-fields", requireAuth, async (req, res) => {
  if (req.user && req.user.org_id && req.user.org_role === 'member') return res.status(403).json({ error: 'member_cannot_edit_templates', message: 'Your team owner manages contract templates.' });
  try {
    const pages = (req.body && req.body.pages) || [];
    if (!Array.isArray(pages) || !pages.length) return res.status(400).json({ error: "No contract pages were provided" });
    if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: "AI is not configured" });
    const content = [];
    for (let i = 0; i < pages.length && i < 8; i++) {
      let raw = String(pages[i] || "");
      const comma = raw.indexOf(",");
      if (raw.slice(0, 5) === "data:" && comma >= 0) raw = raw.slice(comma + 1);
      content.push({ type: "text", text: "PAGE " + (i + 1) + ":" });
      content.push({ type: "image", source: { type: "base64", media_type: "image/png", data: raw } });
    }
    content.push({ type: "text", text: DETECT_FIELDS_PROMPT });
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-6", max_tokens: 2000, messages: [{ role: "user", content: content }] })
    });
    const data = await response.json();
    if (!response.ok) { console.error("[detect-fields] anthropic", response.status, data); return res.status(502).json({ error: "The AI could not read the contract" }); }
    let text = (data.content || []).filter(c => c.type === "text").map(c => c.text).join("").trim();
    const lb = text.indexOf("[");
    const rb = text.lastIndexOf("]");
    if (lb >= 0 && rb > lb) text = text.slice(lb, rb + 1);
    let parsed = [];
    try { parsed = JSON.parse(text); } catch (e) { console.error("[detect-fields] parse failed"); return res.json({ fields: [] }); }
    const fields = Array.isArray(parsed) ? parsed : (parsed.fields || []);
    res.json({ fields: fields });
  } catch (e) {
    console.error("[contracts/detect-fields]", e);
    res.status(500).json({ error: "Field detection failed" });
  }
});

const REBUILD_PROMPT = `You are given a roofing, home improvement, or public adjuster contract document. Transcribe the ENTIRE contract exactly, word for word. Do not summarize, reword, shorten, paraphrase, or omit anything. Every clause, sentence, term, number, percentage, dollar amount, license number, warranty, and notice must be reproduced exactly as written. Identify the structure of the document and estimate the font size of each part so the original sizing is preserved exactly. Return ONLY a JSON object and nothing else, in this exact shape: {"title":"the contract title","title_size":16,"sections":[ ]}. title_size is the point size of the title. Each item in sections must be one of these four forms: {"kind":"heading","text":"a heading exactly as written","size":12} or {"kind":"paragraph","text":"a clause or paragraph transcribed word for word","size":10} or {"kind":"field","label":"the printed label of a fill-in blank","field_id":"an id from the list","multiline":false,"size":10,"signer":"client, client2, or adjuster"} or {"kind":"signature","label":"the party who signs here","signer":"client, client2, or adjuster"}. The size value is your best estimate of the printed font size in points. Typical contract body text is 9 to 12 points. Most body paragraphs share one consistent size, so use the same size for them; only report a different size when the original clearly prints that text larger or smaller. Pay very close attention to any text printed larger or smaller than the body, such as a required legal notice, disclosure, or cancellation notice, and estimate its size accurately, because that exact size must be preserved for legal compliance. For every blank line, underline, or labeled fill-in space, emit a field section. Choose field_id from this list: client_name, property_address, phone, email, carrier, claim_number, price, percentage, scope, agreement_date, date_signed, initials, other. Use percentage for any blank that holds a percent value, such as next to a percent sign, an adjuster fee, a contractor fee, a retainer share, or a percent of net proceeds. Use initials for any spot where the client puts their initials rather than a full signature, such as initialing a page or initialing next to a specific clause. Set multiline to true only for large write-in areas such as the scope or description of work. Represent each signing area as a single signature section. For every signature, initials, and date_signed spot, also set a signer property: use "client" for the primary customer, insured, homeowner, or property owner; use "client2" for a second, different insured or co-owner who has their own separate signature line, such as a co-insured or a spouse or a second property owner; use "adjuster" for the public adjuster, adjuster, contractor, roofer, company, or firm representative. When the document has two separate signature lines on the customer side, use "client" for the first and "client2" for the second. When you cannot tell, use "client". Keep every section in the original reading order and transcribe the document completely from start to finish.`;

app.post("/contracts/rebuild", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: "AI is not configured" });
    const tpl = dsRowsOf(await q("SELECT id, pdf_base64 FROM user_contracts WHERE user_id=$1 AND id = COALESCE($2::int, (SELECT MAX(id) FROM user_contracts WHERE user_id=$1))", [await templateOwnerIdFor(req.user), ((req.body && req.body.contract_id) ? parseInt(req.body.contract_id, 10) : null)]));
    if (!tpl.length || !tpl[0].pdf_base64) return res.status(400).json({ error: "Upload your contract first" });
    let pdfB64 = String(tpl[0].pdf_base64 || "");
    const cidx = pdfB64.indexOf(",");
    if (pdfB64.slice(0, 5) === "data:" && cidx >= 0) pdfB64 = pdfB64.slice(cidx + 1);
    const content = [
      { type: "document", source: { type: "base64", media_type: "application/pdf", data: pdfB64 } },
      { type: "text", text: REBUILD_PROMPT }
    ];
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "anthropic-beta": "pdfs-2024-09-25" },
      body: JSON.stringify({ model: "claude-sonnet-4-6", max_tokens: 8000, messages: [{ role: "user", content: content }] })
    });
    const data = await response.json();
    if (!response.ok) { console.error("[rebuild] anthropic", response.status, data); return res.status(502).json({ error: "The AI could not read the contract" }); }
    let text = (data.content || []).filter(c => c.type === "text").map(c => c.text).join("").trim();
    const lb = text.indexOf("{");
    const rb = text.lastIndexOf("}");
    if (lb >= 0 && rb > lb) text = text.slice(lb, rb + 1);
    let docObj = null;
    try { docObj = JSON.parse(text); } catch (e) { console.error("[rebuild] parse failed"); return res.status(502).json({ error: "The rebuilt contract could not be read. Please try again." }); }
    if (!docObj || !Array.isArray(docObj.sections) || !docObj.sections.length) return res.status(502).json({ error: "The rebuilt contract came back incomplete. Please try again." });
    let previewBuf = null;
    try { previewBuf = await renderContractPdf(docObj, { mode: "blank" }); }
    catch (e) { console.error("[rebuild] render", e); return res.status(500).json({ error: "Could not render the rebuilt contract" }); }
    res.json({ doc: docObj, contract_id: (tpl[0] && tpl[0].id) || null, preview_pdf_base64: Buffer.from(previewBuf).toString("base64") });
  } catch (e) {
    console.error("[contracts/rebuild]", e);
    res.status(500).json({ error: "Contract rebuild failed" });
  }
});

app.post("/contracts/rebuild/save", requireAuth, async (req, res) => {
  if (req.user && req.user.org_id && req.user.org_role === 'member') return res.status(403).json({ error: 'member_cannot_edit_templates', message: 'Your team owner manages contract templates.' });
  try {
    await ensureContractsSchema();
    const doc = req.body && req.body.doc;
    if (!doc || !Array.isArray(doc.sections) || !doc.sections.length) return res.status(400).json({ error: "Invalid contract document" });
    await q("UPDATE user_contracts SET doc_json=$1 WHERE user_id=$2 AND id = COALESCE($3::int, (SELECT MAX(id) FROM user_contracts WHERE user_id=$2))", [JSON.stringify(doc), req.user.id, ((req.body && req.body.contract_id) ? parseInt(req.body.contract_id, 10) : null)]);
    res.json({ ok: true });
  } catch (e) {
    console.error("[contracts/rebuild:save]", e);
    res.status(500).json({ error: "Could not save the rebuilt contract" });
  }
});

app.get("/contracts/templates", requireAuth, async (req, res) => {
  try { req.user.id = await templateOwnerIdFor(req.user); } catch (e) {}
  try {
    await ensureContractsSchema();
    const rows = dsRowsOf(await q("SELECT id, name, filename, uploaded_at, (doc_json IS NOT NULL) AS has_doc FROM user_contracts WHERE user_id=$1 ORDER BY id DESC", [req.user.id]));
    res.json({ contracts: rows });
  } catch (e) {
    console.error("[contracts/templates]", e);
    res.status(500).json({ error: "Could not load contracts" });
  }
});

app.get("/contracts/signed/:id", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    if (!DS_API_KEY) return res.status(500).json({ error: "E-signature is not configured" });
    const rows = dsRowsOf(await q("SELECT signature_request_id, status, signer_name FROM contracts WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]));
    if (!rows.length) return res.status(404).json({ error: "Contract not found" });
    const row = rows[0];
    if (!row.signature_request_id) return res.status(400).json({ error: "No signed document available" });
    const dsRes = await fetch(DS_BASE + "/signature_request/files/" + encodeURIComponent(row.signature_request_id) + "?file_type=pdf", {
      headers: { "Authorization": dsAuthHeader() }
    });
    if (!dsRes.ok) return res.status(502).json({ error: "The signed document is not ready yet" });
    const buf = Buffer.from(await dsRes.arrayBuffer());
    const safeName = String(row.signer_name || "contract").replace(/[^a-zA-Z0-9]+/g, "-");
    res.json({ filename: "Signed-" + safeName + ".pdf", pdf_base64: buf.toString("base64") });
  } catch (e) {
    console.error("[contracts/signed]", e);
    res.status(500).json({ error: "Could not load the signed document" });
  }
});

/* =================== END CONTRACTS / E-SIGNATURE =================== */

/* ===================== AGREEMENT SUMMARY PAGE ===================== */
function apWrap(text, font, size, maxWidth) {
  var words = String(text == null ? "" : text).split(" ");
  var lines = [], line = "";
  for (var i = 0; i < words.length; i++) {
    var w = words[i];
    if (!w) continue;
    var test = line ? line + " " + w : w;
    if (font.widthOfTextAtSize(test, size) > maxWidth && line) { lines.push(line); line = w; }
    else line = test;
  }
  if (line) lines.push(line);
  return lines;
}

async function buildAgreementPdf(contractBytes, body, user) {
  body = body || {};
  const merged = await PDFDocument.create();
  const font = await merged.embedFont(StandardFonts.Helvetica);
  const bold = await merged.embedFont(StandardFonts.HelveticaBold);
  const W = 612, H = 792, M = 56;
  const ink = rgb(0.17, 0.15, 0.13);
  const muted = rgb(0.49, 0.45, 0.40);
  const accent = rgb(1, 0.42, 0.21);
  const page = merged.addPage([W, H]);
  let y = H - 62;
  const firm = String(body.firm_name || "Roofing Agreement");
  page.drawText(firm.toUpperCase().slice(0, 46), { x: M, y: y, size: 18, font: bold, color: ink });
  y -= 20;
  page.drawText("Service Agreement and Scope of Work", { x: M, y: y, size: 11, font: font, color: muted });
  y -= 14;
  page.drawLine({ start: { x: M, y: y }, end: { x: W - M, y: y }, thickness: 2, color: accent });
  y -= 30;
  function section(label) {
    page.drawText(label, { x: M, y: y, size: 9, font: bold, color: accent });
    y -= 18;
  }
  function row(label, value) {
    if (value == null || value === "") return;
    page.drawText(String(label).toUpperCase(), { x: M, y: y, size: 8.5, font: bold, color: muted });
    var v = String(value);
    page.drawText(v.length > 60 ? v.slice(0, 57) + "..." : v, { x: M + 145, y: y, size: 11, font: font, color: ink });
    y -= 21;
  }
  section("CLIENT AND PROPERTY");
  row("Client", body.signer_name);
  row("Email", body.signer_email);
  row("Phone", body.signer_phone);
  row("Property", body.property_address);
  row("Insurance Carrier", body.carrier);
  row("Claim Number", body.claim_number);
  row("Date of Loss", body.date_of_loss);
  y -= 10;
  section("PRICING");
  page.drawRectangle({ x: M, y: y - 26, width: W - 2 * M, height: 46, color: rgb(0.96, 0.93, 0.85) });
  page.drawText("CONTRACT PRICE", { x: M + 14, y: y + 4, size: 8.5, font: bold, color: muted });
  page.drawText(String(body.price || "To be determined"), { x: M + 14, y: y - 16, size: 17, font: bold, color: ink });
  y -= 48;
  if (body.scope && String(body.scope).trim()) {
    y -= 14;
    section("SCOPE OF WORK");
    var sl = apWrap(body.scope, font, 10, W - 2 * M);
    for (var si = 0; si < sl.length && y > 232; si++) { page.drawText(sl[si], { x: M, y: y, size: 10, font: font, color: ink }); y -= 14; }
  }
  y -= 22;
  var agree = "By signing below, the client authorizes " + firm + " to perform the work described above at the stated price. The complete terms and conditions follow on the attached pages and form part of this agreement.";
  var al = apWrap(agree, font, 9, W - 2 * M);
  for (var ai = 0; ai < al.length; ai++) { page.drawText(al[ai], { x: M, y: y, size: 9, font: font, color: muted }); y -= 12.5; }
  y -= 46;
  page.drawLine({ start: { x: M, y: y }, end: { x: M + 235, y: y }, thickness: 1, color: ink });
  page.drawLine({ start: { x: W - M - 150, y: y }, end: { x: W - M, y: y }, thickness: 1, color: ink });
  page.drawText("[sig|req|signer1]", { x: M, y: y + 7, size: 6, font: font, color: rgb(1, 1, 1) });
  page.drawText("[date|req|signer1]", { x: W - M - 150, y: y + 7, size: 6, font: font, color: rgb(1, 1, 1) });
  y -= 13;
  page.drawText("Client Signature", { x: M, y: y, size: 8.5, font: font, color: muted });
  page.drawText("Date Signed", { x: W - M - 150, y: y, size: 8.5, font: font, color: muted });
  try {
    const src = await PDFDocument.load(contractBytes, { ignoreEncryption: true });
    const copied = await merged.copyPages(src, src.getPageIndices());
    for (var ci = 0; ci < copied.length; ci++) merged.addPage(copied[ci]);
  } catch (e) {
    console.error("[buildAgreementPdf] contract merge failed", e);
    throw new Error("contract-merge-failed");
  }
  return await merged.save();
}

async function fillContractPdf(contractBytes, fieldMap, body, user) {
  body = body || {};
  const pdf = await PDFDocument.load(contractBytes, { ignoreEncryption: true });
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const pages = pdf.getPages();
  const ink = rgb(0.1, 0.1, 0.13);
  const white = rgb(1, 1, 1);
  const today = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  function valueFor(type) {
    if (type === "client_name") return body.signer_name || body.claim_name || "";
    if (type === "property_address") return body.property_address || body.address || "";
    if (type === "phone") return body.phone || "";
    if (type === "email") return body.signer_email || "";
    if (type === "carrier") return body.carrier || body.insurance_carrier || "";
    if (type === "claim_number") return body.claim_number || body.claim_no || "";
    if (type === "price") { var p = body.price ? String(body.price).trim() : ""; return p ? (p.charAt(0) === "$" ? p : "$" + p) : ""; }
    if (type === "scope") return body.scope || "";
    if (type === "agreement_date") return today;
    return "";
  }
  let sigCount = 0;
  const list = Array.isArray(fieldMap) ? fieldMap : [];
  for (let i = 0; i < list.length; i++) {
    const f = list[i] || {};
    const pageIdx = (f.page || 1) - 1;
    if (pageIdx < 0 || pageIdx >= pages.length) continue;
    const pg = pages[pageIdx];
    const sz = pg.getSize();
    const pw = sz.width, ph = sz.height;
    const x = (Number(f.x) || 0) * pw;
    const fh = (Number(f.h) || 0.025) * ph;
    const fw = Math.max(36, (Number(f.w) || 0.3) * pw);
    const yTop = (Number(f.y) || 0) * ph;
    const baseline = ph - yTop - fh * 0.78;
    if (f.type === "signature") {
      sigCount++;
      pg.drawText("[sig|req|signer1]", { x: x + 2, y: baseline, size: 7, font: font, color: white });
    } else if (f.type === "date_signed") {
      pg.drawText("[date|req|signer1]", { x: x + 2, y: baseline, size: 7, font: font, color: white });
    } else {
      const val = valueFor(f.type);
      if (val) {
        let size = 11;
        while (size > 6 && font.widthOfTextAtSize(String(val), size) > fw) size -= 0.5;
        pg.drawText(String(val), { x: x + 2, y: baseline, size: size, font: font, color: ink });
      }
    }
  }
  if (sigCount === 0) {
    const last = pages[pages.length - 1];
    const ls = last.getSize();
    last.drawText("[sig|req|signer1]", { x: 60, y: 70, size: 7, font: font, color: white });
    last.drawText("[date|req|signer1]", { x: ls.width - 180, y: 70, size: 7, font: font, color: white });
  }
  return await pdf.save();
}

async function renderContractPdf(doc, opts) {
  opts = opts || {};
  var mode = opts.mode || "blank";
  var body = opts.body || {};
  var fieldValues = Array.isArray(body.field_values) ? body.field_values : null;
  var signerMap = opts.signer_map || null;
  var pdf = await PDFDocument.create();
  var font = await pdf.embedFont(StandardFonts.Helvetica);
  var bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  var W = 612, H = 792, M = 58;
  var CW = W - 2 * M;
  var ink = rgb(0.13, 0.12, 0.11);
  var soft = rgb(0.42, 0.39, 0.35);
  var line = rgb(0.62, 0.59, 0.54);
  var white = rgb(1, 1, 1);
  var accent = rgb(1, 0.42, 0.21);
  var page = pdf.addPage([W, H]);
  var y = H - M;
  function newPage() { page = pdf.addPage([W, H]); y = H - M; }
  function need(hh) { if (y - hh < M + 14) newPage(); }
  function clampSize(v, def) { var n = Number(v); if (!n || n < 6 || n > 30) return def; return n; }
  function sgnr(x) { var role = (x && x.signer) || "client"; return (signerMap && signerMap[role]) || "signer1"; }
  function todayStr() { return new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }); }
  function wa(v) {
    var s = String(v == null ? "" : v);
    var map = { 8216:39, 8217:39, 8218:39, 8219:39, 8242:39, 8220:34, 8221:34, 8222:34, 8223:34, 8243:34, 8208:45, 8209:45, 8210:45, 8211:45, 8212:45, 8213:45, 8722:45, 8226:45, 8227:45, 9679:45, 9642:45, 183:45, 8259:45, 160:32, 8194:32, 8195:32, 8201:32, 8202:32, 8199:32, 8239:32, 8203:-1, 8204:-1, 8205:-1, 65279:-1 };
    var out = "";
    for (var i = 0; i < s.length; i++) {
      var cc = s.charCodeAt(i);
      if (cc === 10 || cc === 13 || cc === 9 || cc === 12 || cc === 11) { out = out + " "; continue; }
      if (map.hasOwnProperty(cc)) { var mm = map[cc]; if (mm >= 0) out = out + String.fromCharCode(mm); continue; }
      if (cc === 8230) { out = out + "..."; continue; }
      if (cc === 8482) { out = out + "(TM)"; continue; }
      if (cc === 64257) { out = out + "fi"; continue; }
      if (cc === 64258) { out = out + "fl"; continue; }
      if ((cc >= 32 && cc <= 126) || (cc >= 160 && cc <= 255)) { out = out + s.charAt(i); continue; }
    }
    return out;
  }
  function valueFor(id) {
    if (id === "client_name") return body.signer_name || body.claim_name || "";
    if (id === "property_address") return body.property_address || body.address || "";
    if (id === "phone") return body.signer_phone || body.phone || "";
    if (id === "email") return body.signer_email || "";
    if (id === "carrier") return body.carrier || body.insurance_carrier || "";
    if (id === "claim_number") return body.claim_number || "";
    if (id === "price") { var p = body.price ? String(body.price).trim() : ""; return p ? (p.charAt(0) === "$" ? p : "$" + p) : ""; }
    if (id === "scope") return body.scope || "";
    if (id === "agreement_date") return todayStr();
    return "";
  }
  function drawWrapped(text, fnt, size, color) {
    var lh = size * 1.34;
    var ls = apWrap(wa(text), fnt, size, CW);
    for (var i = 0; i < ls.length; i++) {
      need(lh);
      page.drawText(ls[i], { x: M, y: y - size, size: size, font: fnt, color: color });
      y -= lh;
    }
  }
  if (doc.title) {
    var t = wa(doc.title).toUpperCase();
    var ts = clampSize(doc.title_size, 17);
    while (ts > 10 && bold.widthOfTextAtSize(t, ts) > CW) ts -= 0.5;
    need(ts + 18);
    page.drawText(t, { x: M + (CW - bold.widthOfTextAtSize(t, ts)) / 2, y: y - ts, size: ts, font: bold, color: ink });
    y -= ts + 9;
    page.drawLine({ start: { x: M, y: y }, end: { x: W - M, y: y }, thickness: 1.4, color: accent });
    y -= 20;
  }
  var sawSig = false;
  var fieldIdx = 0;
  var sections = Array.isArray(doc.sections) ? doc.sections : [];
  for (var s = 0; s < sections.length; s++) {
    var sec = sections[s] || {};
    var kind = sec.kind || "paragraph";
    if (kind === "heading") {
      var hs = clampSize(sec.size, 11);
      y -= hs * 0.7;
      need(hs * 1.6);
      page.drawText(wa(sec.text).toUpperCase(), { x: M, y: y - hs, size: hs, font: bold, color: ink });
      y -= hs * 1.5;
    } else if (kind === "paragraph") {
      if (sec.text) { var ps = clampSize(sec.size, 10.5); drawWrapped(sec.text, font, ps, ink); y -= ps * 0.5; }
    } else if (kind === "field") {
      var label = wa(sec.label || "Field");
      var fid = sec.field_id || "other";
      var fs = clampSize(sec.size, 10.5);
      var fno = fieldIdx; fieldIdx++;
      var ov = (mode === "filled" && fieldValues && fieldValues[fno] != null && String(fieldValues[fno]).trim() !== "") ? String(fieldValues[fno]) : "";
      var val = (mode === "filled") ? (ov || valueFor(fid)) : "";
      if (sec.multiline) {
        need(fs * 6);
        page.drawText(label + ":", { x: M, y: y - fs, size: fs, font: bold, color: ink });
        y -= fs * 1.6;
        if (val) { drawWrapped(val, font, fs, ink); y -= fs * 0.5; }
        else { for (var k = 0; k < 3; k++) { need(fs * 1.8); page.drawLine({ start: { x: M, y: y - 2 }, end: { x: W - M, y: y - 2 }, thickness: 0.7, color: line }); y -= fs * 1.8; } y -= 3; }
      } else {
        need(fs * 2.3);
        var lab = label + ":  ";
        var lw = bold.widthOfTextAtSize(lab, fs);
        page.drawText(lab, { x: M, y: y - fs, size: fs, font: bold, color: ink });
        var underY = y - fs - 1.5;
        if (mode === "filled" && fid === "signature") {
          page.drawLine({ start: { x: M + lw, y: underY }, end: { x: W - M, y: underY }, thickness: 1, color: ink });
          page.drawText("[sig|req|" + sgnr(sec) + "]", { x: M + lw + 2, y: underY + 2, size: 7, font: font, color: white });
          sawSig = true;
        } else if (mode === "filled" && fid === "date_signed") {
          page.drawLine({ start: { x: M + lw, y: underY }, end: { x: W - M, y: underY }, thickness: 1, color: ink });
          page.drawText("[date|req|" + sgnr(sec) + "]", { x: M + lw + 2, y: underY + 2, size: 7, font: font, color: white });
        } else if (mode === "filled" && fid === "initials") {
          page.drawLine({ start: { x: M + lw, y: underY }, end: { x: M + lw + 90, y: underY }, thickness: 1, color: ink });
          page.drawText("[initial|req|" + sgnr(sec) + "]", { x: M + lw + 2, y: underY + 2, size: 7, font: font, color: white });
        } else if (fid === "percentage") {
          var _pctVal = val ? String(val).trim() : "";
          if (_pctVal.charAt(_pctVal.length - 1) === "%") _pctVal = _pctVal.slice(0, -1).trim();
          page.drawLine({ start: { x: M + lw, y: underY }, end: { x: M + lw + 60, y: underY }, thickness: 0.7, color: line });
          if (_pctVal) page.drawText(wa(_pctVal), { x: M + lw + 4, y: y - fs, size: fs, font: font, color: ink });
          page.drawText("%", { x: M + lw + 66, y: y - fs, size: fs, font: bold, color: ink });
        } else if (val) {
          page.drawText(wa(val), { x: M + lw, y: y - fs, size: fs, font: font, color: ink });
        } else {
          page.drawLine({ start: { x: M + lw, y: underY }, end: { x: W - M, y: underY }, thickness: 0.7, color: line });
        }
        y -= fs * 2.3;
      }
    } else if (kind === "signature") {
      var slabel = wa(sec.label || "Signature");
      y -= 22;
      need(60);
      var colW = (CW - 34) / 2;
      page.drawLine({ start: { x: M, y: y }, end: { x: M + colW, y: y }, thickness: 1, color: ink });
      page.drawLine({ start: { x: M + colW + 34, y: y }, end: { x: W - M, y: y }, thickness: 1, color: ink });
      if (mode === "filled") {
        page.drawText("[sig|req|" + sgnr(sec) + "]", { x: M + 2, y: y + 7, size: 7, font: font, color: white });
        page.drawText("[date|req|" + sgnr(sec) + "]", { x: M + colW + 36, y: y + 7, size: 7, font: font, color: white });
        sawSig = true;
      }
      y -= 13;
      page.drawText(slabel, { x: M, y: y, size: 8.5, font: font, color: soft });
      page.drawText("Date", { x: M + colW + 34, y: y, size: 8.5, font: font, color: soft });
      y -= 20;
    }
  }
  if (mode === "filled" && !sawSig) {
    need(60);
    y -= 16;
    var cw2 = (CW - 34) / 2;
    page.drawLine({ start: { x: M, y: y }, end: { x: M + cw2, y: y }, thickness: 1, color: ink });
    page.drawLine({ start: { x: M + cw2 + 34, y: y }, end: { x: W - M, y: y }, thickness: 1, color: ink });
    page.drawText("[sig|req|signer1]", { x: M + 2, y: y + 7, size: 7, font: font, color: white });
    page.drawText("[date|req|signer1]", { x: M + cw2 + 36, y: y + 7, size: 7, font: font, color: white });
    y -= 13;
    page.drawText("Client Signature", { x: M, y: y, size: 8.5, font: font, color: soft });
    page.drawText("Date Signed", { x: M + cw2 + 34, y: y, size: 8.5, font: font, color: soft });
  }
  return await pdf.save();
}
/* =================== END AGREEMENT SUMMARY PAGE =================== */


/* ===================== ROOF MEASUREMENT (Google Solar API) ===================== */
async function geocodeUS(address) {
  if (!address || !String(address).trim()) return null;
  const q = String(address).trim();
  // Step 1: US Census geocoder - free, no key
  try {
    const cu = "https://geocoding.geo.census.gov/geocoder/locations/onelineaddress?address=" + encodeURIComponent(q) + "&benchmark=2020&format=json";
    const cr = await fetch(cu);
    if (cr.ok) {
      const cj = await cr.json();
      const m = cj && cj.result && cj.result.addressMatches && cj.result.addressMatches[0];
      if (m && m.coordinates && m.coordinates.y && m.coordinates.x) {
        return { lat: Number(m.coordinates.y), lng: Number(m.coordinates.x), source: "census" };
      }
    }
  } catch (e) {}
  // Step 2: OpenStreetMap Nominatim fallback - free, no key
  try {
    const nu = "https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=us&q=" + encodeURIComponent(q);
    const nr = await fetch(nu, { headers: { "User-Agent": "HailGrade/1.0 claims@smithadjusters.com" } });
    if (nr.ok) {
      const nj = await nr.json();
      if (Array.isArray(nj) && nj[0] && nj[0].lat && nj[0].lon) {
        return { lat: Number(nj[0].lat), lng: Number(nj[0].lon), source: "nominatim" };
      }
    }
  } catch (e) {}
  return null;
}

app.post("/roof/measure", requireAuth, async (req, res) => {
  try {
    const key = process.env.GOOGLE_SOLAR_API_KEY || "";
    if (!key) return res.status(503).json({ error: "Roof measurement is not set up yet" });
    const body = req.body || {};
    let lat = (typeof body.lat === "number") ? body.lat : null;
    let lng = (typeof body.lng === "number") ? body.lng : null;
    if ((lat == null || lng == null) && body.address) {
      const g = await geocodeUS(String(body.address));
      if (!g) return res.status(404).json({ error: "Could not locate that address" });
      lat = g.lat; lng = g.lng;
    }
    if (lat == null || lng == null || isNaN(lat) || isNaN(lng)) {
      return res.status(400).json({ error: "Need a property address or photo GPS" });
    }
    const url = "https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=" +
      encodeURIComponent(lat) + "&location.longitude=" + encodeURIComponent(lng) +
      "&key=" + encodeURIComponent(key);
    const r = await fetch(url);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      if (r.status === 404) return res.status(404).json({ error: "No roof imagery available for this property" });
      console.error("[roof/measure] solar error", r.status, JSON.stringify(j).slice(0, 300));
      return res.status(502).json({ error: "Roof measurement service is unavailable" });
    }
    const sp = j.solarPotential || {};
    const stats = sp.wholeRoofStats || {};
    const areaM2 = Number(stats.areaMeters2 || 0);
    if (!areaM2) return res.status(404).json({ error: "No roof area found for this property" });
    const sqft = areaM2 * 10.76391;
    const segments = Array.isArray(sp.roofSegmentStats) ? sp.roofSegmentStats.length : null;

    // --- Aerial roof image + roof-plane outlines (Google Static Maps) ---
    let roofImg = null, roofImgType = null, mapMeta = null;
    const segBoxes = [];
    try {
      const segStats = Array.isArray(sp.roofSegmentStats) ? sp.roofSegmentStats : [];
      let minLat = lat, maxLat = lat, minLng = lng, maxLng = lng;
      segStats.forEach(function (s) {
        const bb = s && s.boundingBox;
        if (!bb || !bb.sw || !bb.ne) return;
        const sLat = Number(bb.sw.latitude), nLat = Number(bb.ne.latitude);
        const wLng = Number(bb.sw.longitude), eLng = Number(bb.ne.longitude);
        if ([sLat, nLat, wLng, eLng].some(isNaN)) return;
        minLat = Math.min(minLat, sLat, nLat); maxLat = Math.max(maxLat, sLat, nLat);
        minLng = Math.min(minLng, wLng, eLng); maxLng = Math.max(maxLng, wLng, eLng);
        segBoxes.push({
          area_m2: Math.round(Number((s.stats && s.stats.areaMeters2) || 0)),
          pitch: (s.pitchDegrees != null) ? Math.round(s.pitchDegrees) : null,
          azimuth: (s.azimuthDegrees != null) ? Math.round(s.azimuthDegrees) : null,
          sw: { lat: sLat, lng: wLng },
          ne: { lat: nLat, lng: eLng }
        });
      });
      const padLat = Math.max((maxLat - minLat) * 0.25, 0.00012);
      const padLng = Math.max((maxLng - minLng) * 0.25, 0.00012);
      minLat -= padLat; maxLat += padLat; minLng -= padLng; maxLng += padLng;
      const ctrLat = (minLat + maxLat) / 2, ctrLng = (minLng + maxLng) / 2;
      let zoom = 21;
      for (; zoom > 16; zoom--) {
        const worldPx = 256 * Math.pow(2, zoom);
        const xOf = function (L) { return (L + 180) / 360 * worldPx; };
        const yOf = function (L) { let si = Math.sin(L * Math.PI / 180); si = Math.max(-0.9999, Math.min(0.9999, si)); return (0.5 - Math.log((1 + si) / (1 - si)) / (4 * Math.PI)) * worldPx; };
        if (Math.abs(xOf(maxLng) - xOf(minLng)) <= 620 && Math.abs(yOf(maxLat) - yOf(minLat)) <= 620) break;
      }
      const mapUrl = "https://maps.googleapis.com/maps/api/staticmap?center=" +
        ctrLat + "," + ctrLng + "&zoom=" + zoom +
        "&size=640x640&scale=2&maptype=satellite&format=jpg&key=" + encodeURIComponent(key);
      const mr = await fetch(mapUrl);
      const ctype = (mr.headers.get("content-type") || "");
      if (mr.ok && ctype.indexOf("image") === 0) {
        const ab = await mr.arrayBuffer();
        roofImg = Buffer.from(ab).toString("base64");
        roofImgType = ctype.split(";")[0];
        mapMeta = { center: { lat: ctrLat, lng: ctrLng }, zoom: zoom, width: 1280, height: 1280, scale: 2 };
      } else {
        console.error("[roof/measure] static map unavailable", mr.status, ctype);
      }
    } catch (me) {
      console.error("[roof/measure] image step failed", me && me.message);
    }

    res.json({
      squares: Math.round((sqft / 100) * 10) / 10,
      area_sqft: Math.round(sqft),
      area_m2: Math.round(areaM2),
      segments: segments,
      lat: lat, lng: lng,
      image_base64: roofImg,
      image_media_type: roofImgType,
      map: mapMeta,
      roof_segments: segBoxes
    });
  } catch (e) {
    console.error("[roof/measure]", e);
    res.status(500).json({ error: "Could not measure the roof" });
  }
});
/* =================== END ROOF MEASUREMENT =================== */

app.post("/places/suggest", requireAuth, async (req, res) => {
  try {
    const key = process.env.GOOGLE_SOLAR_API_KEY || "";
    if (!key) return res.status(503).json({ error: "not_configured" });
    const q = String((req.body && req.body.q) || "").trim();
    if (q.length < 3) return res.json({ suggestions: [] });
    const r = await fetch("https://places.googleapis.com/v1/places:autocomplete", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Goog-Api-Key": key },
      body: JSON.stringify({ input: q, includedRegionCodes: ["us"] })
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      console.error("[places/suggest]", r.status, JSON.stringify(j).slice(0, 200));
      return res.status(502).json({ error: "places_unavailable" });
    }
    const out = (j.suggestions || []).map(function (s) {
      const p = s.placePrediction || {};
      return { placeId: p.placeId || "", text: (p.text && p.text.text) || "" };
    }).filter(function (x) { return x.placeId && x.text; });
    res.json({ suggestions: out });
  } catch (e) {
    console.error("[places/suggest]", e);
    res.status(500).json({ error: "suggest_failed" });
  }
});

app.post("/places/details", requireAuth, async (req, res) => {
  try {
    const key = process.env.GOOGLE_SOLAR_API_KEY || "";
    if (!key) return res.status(503).json({ error: "not_configured" });
    const pid = String((req.body && req.body.place_id) || "").trim();
    if (!pid) return res.status(400).json({ error: "place_id_required" });
    const r = await fetch("https://places.googleapis.com/v1/places/" + encodeURIComponent(pid), {
      headers: { "X-Goog-Api-Key": key, "X-Goog-FieldMask": "formattedAddress,location" }
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      console.error("[places/details]", r.status, JSON.stringify(j).slice(0, 200));
      return res.status(502).json({ error: "details_unavailable" });
    }
    res.json({
      address: j.formattedAddress || "",
      lat: (j.location && j.location.latitude != null) ? j.location.latitude : null,
      lng: (j.location && j.location.longitude != null) ? j.location.longitude : null
    });
  } catch (e) {
    console.error("[places/details]", e);
    res.status(500).json({ error: "details_failed" });
  }
});

app.post("/cloud/jobs", requireAuth, async (req, res) => {
  try {
    const b = req.body || {};
    const jobId = String(b.job_id || "").trim();
    const payload = (typeof b.payload === "string") ? b.payload : "";
    if (!jobId || !payload) return res.status(400).json({ error: "job_id and payload required" });
    if (payload.length > 56 * 1024 * 1024) return res.status(413).json({ error: "That job is too large to move to the cloud" });
    const name = String(b.name || "Job").slice(0, 200);
    await q("DELETE FROM cloud_jobs WHERE user_id=$1 AND job_id=$2", [req.user.id, jobId]);
    await q("INSERT INTO cloud_jobs (user_id, job_id, name, payload, size_bytes, updated_at) VALUES ($1,$2,$3,$4,$5, now())", [req.user.id, jobId, name, payload, payload.length]);
    res.json({ ok: true });
  } catch (e) {
    console.error("[cloud/jobs POST]", e);
    res.status(500).json({ error: "Could not move the job to the cloud" });
  }
});

app.get("/cloud/jobs", requireAuth, async (req, res) => {
  try {
    const rows = await q("SELECT job_id, name, size_bytes, updated_at FROM cloud_jobs WHERE user_id=$1 ORDER BY updated_at DESC", [req.user.id]);
    res.json({ jobs: rows });
  } catch (e) {
    console.error("[cloud/jobs GET]", e);
    res.status(500).json({ error: "Could not load cloud jobs" });
  }
});

app.get("/cloud/jobs/:jobId", requireAuth, async (req, res) => {
  try {
    const rows = await q("SELECT payload, name FROM cloud_jobs WHERE user_id=$1 AND job_id=$2", [req.user.id, String(req.params.jobId)]);
    if (!rows.length) return res.status(404).json({ error: "Not found in the cloud" });
    res.json({ payload: rows[0].payload, name: rows[0].name });
  } catch (e) {
    console.error("[cloud/jobs/:id GET]", e);
    res.status(500).json({ error: "Could not download the job" });
  }
});

app.delete("/cloud/jobs/:jobId", requireAuth, async (req, res) => {
  try {
    await q("DELETE FROM cloud_jobs WHERE user_id=$1 AND job_id=$2", [req.user.id, String(req.params.jobId)]);
    res.json({ ok: true });
  } catch (e) {
    console.error("[cloud/jobs/:id DELETE]", e);
    res.status(500).json({ error: "Could not remove the job" });
  }
});

function haversineMi(lat1, lng1, lat2, lng2) {
  const R = 3958.8;
  const toRad = d => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

// ============ Stripe webhook ============
async function handleStripeWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[webhook] signature failed', err.message);
    return res.status(400).send('signature failed');
  }

  // Idempotency
  const seen = await one('SELECT id FROM stripe_events WHERE id = $1', [event.id]);
  if (seen) return res.json({ ok: true, duplicate: true });

  try {
    switch (event.type) {
      case 'checkout.session.completed':
      case 'customer.subscription.created':
      case 'customer.subscription.updated': {
        const sub = event.type === 'checkout.session.completed'
          ? await stripe.subscriptions.retrieve(event.data.object.subscription)
          : event.data.object;
        const customerId = sub.customer;
        const plan = sub.items.data[0]?.price?.id === process.env.STRIPE_PRICE_FIRM ? 'firm' : 'solo';
        await q(
          `UPDATE users SET plan = $1, plan_status = $2, plan_renews_at = to_timestamp($3)
           WHERE stripe_customer_id = $4`,
          [plan, sub.status, sub.current_period_end, customerId]
        );
        break;
      }
      case 'customer.subscription.deleted': {
        const customerId = event.data.object.customer;
        await q(
          `UPDATE users SET plan_status = 'canceled' WHERE stripe_customer_id = $1`,
          [customerId]
        );
        break;
      }
      case 'invoice.payment_failed': {
        const customerId = event.data.object.customer;
        await q(
          `UPDATE users SET plan_status = 'past_due' WHERE stripe_customer_id = $1`,
          [customerId]
        );
        break;
      }
    }
    await q('INSERT INTO stripe_events (id, type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING', [event.id, event.type]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[webhook handler]', err);
    res.status(500).json({ ok: false });
  }
}

// ============ Prompt (mirrors what the frontend used to send) ============
function buildAnalysisPrompt({ slope, dateOfLoss, carrier, testSquare }) {
  let testNote = '';
  if (testSquare) {
    testNote = `\nA test square overlay was placed on the image. The user marked ${testSquare.hits} hit point(s) inside it. Count these as confirmed impacts. The test square covers approximately ${Math.round(testSquare.w)}% x ${Math.round(testSquare.h)}% of the frame.`;
  }
  let contextNote = '';
  if (dateOfLoss || carrier) {
    contextNote = `\nClaim context: ${dateOfLoss ? `Date of loss: ${dateOfLoss}. ` : ''}${carrier ? `Carrier: ${carrier}.` : ''}`.trim();
  }

  return `You are a senior roof damage expert advising PUBLIC ADJUSTERS and ROOFING CONTRACTORS. Your job is to identify documentable storm damage when it is present, and to clearly report NO DAMAGE when it is not. A false-positive finding destroys an adjuster's credibility with a carrier. A missed real finding costs the homeowner money. Both errors matter. Be specific, evidence-driven, and honest.

Photo slope: ${slope || 'unknown'}.${contextNote}${testNote}

============================================================
WHAT IS *NOT* DAMAGE — DO NOT HALLUCINATE
============================================================

Before you flag anything, read this list. A healthy asphalt-shingle roof has features that look superficially like damage but are not. Do not report any of these as findings:

1. **Course overlap shadow lines.** Every asphalt shingle has a thin DARK HORIZONTAL LINE at its BOTTOM edge, because the next course of shingles overlaps the top half of each shingle and the bottom edge sits proud and casts a shadow. This shadow line runs across EVERY shingle on a healthy roof, in EVERY photo. It is NOT a crease. A real crease is on the EXPOSED FACE of ONE tab and appears as a fold or bend line, distinct from the natural course shadow at the tab's bottom edge.

2. **Multi-color / blended granules.** Modern dimensional ("architectural") shingles are manufactured with intentional color variation — some tabs are reddish-brown, some gray, some tan, in a random mix. This is the product design, not weathering and not damage. Do NOT call a multi-tone shingle field "differential aging" or "two-tone hail zone."

3. **Natural shadows at hips, ridges, and valleys.** Where two slopes meet, shingles butt against ridge caps or hip caps. The transition creates shadow lines and apparent edge irregularity. This is not "lifted tabs" or "displaced shingles." Verify true lift by looking for the underside of a shingle being visible, daylight under the tab, or exposed nail heads — not just a shadow at the ridge transition.

3a. **Hip and ridge cap shingles.** Cap shingles are folded individual pieces installed along ridge and hip lines as a separate course on top of the field shingles. By design they sit PROUD of the field — their bottom edge is elevated above the adjacent field course. They do not lie flat. A cap shingle visible in the upper portion of a slope photo (near where two roof planes meet) is almost certainly the hip cap, NOT a lifted field tab. Do not call hip/ridge cap shingles "lifted", "creased", "displaced", or "broken seal". Only flag a cap if a tab is visibly missing, torn, or rotated out of its expected position.

3b. **Edge-of-frame shingle artifacts.** A shingle at the extreme edge of the camera frame may appear to lift or angle due to camera perspective and lens distortion. If the only "anomaly" you can find is at the very edge of the image and is not corroborated by other indicators in the centered field of view, do not flag it.

3c. **Ridge vents and shingle-over ridge vents.** A ridge vent runs continuously along the PEAK (ridge) of the roof to ventilate the attic. The common "shingle-over" type is a strip of vent material laid over a slot cut in the decking and then capped with ridge shingles — by design it has air gaps and a slightly raised profile, and from above it can look like a dark line, a thin recessed slot, or a stepped strip running along the ridge. This is INTENTIONAL ventilation, not damage. Do NOT flag a ridge vent or its air gap as a "missing shingle", "gap", "creasing", "displaced tab", or "granular loss". A continuous dark line along the peak of the roof is a ridge vent — examine it as a vent, not as a row of damaged tabs. The ONLY ridge-vent damage worth flagging is the vent material visibly torn loose, ridge cap shingles actually missing off the vent, or the vent crushed/displaced out of line — not the normal vent gap.

4. **Normal granule color variation across the slope.** Shingles oxidize unevenly over years. Some patches will look lighter or darker. Without LOCAL impact indicators (round mat exposure, fresh fracture, halo with intact surround), this is age, not hail.

5. **Roof junk that isn't damage.** Leaves, twigs, pollen stains, algae streaks, lichen patches, satellite dishes, vents, pipe boots, footwear marks, sealant smears — none of these are storm damage on their own.

6. **Camera artifacts.** JPEG compression, motion blur, lens distortion, low contrast in shadowed areas, glare patches — do not interpret as damage.

If you cannot point to a SPECIFIC visual indicator on a SPECIFIC tab or zone that matches the strict definitions below, return no finding for that area. It is correct and expected for a healthy roof photo to return findings: [] and claim_strength: "no-claim".

DO NOT add a "wear_tear" finding just to describe normal age signs on a roof. The wear_tear category exists ONLY to document a pre-existing condition that a carrier will try to use against an otherwise legitimate storm finding. If there is no storm finding being made, do not add a wear_tear finding either — just return findings: []. Normal weathered roofs do not need to be documented as damaged.

============================================================
CONFIDENCE & LANGUAGE DISCIPLINE
============================================================

Match your language to what you actually see:
- If a damage signature is clearly visible (a crease, a missing shingle, a lifted tab, a hail bruise) describe it AFFIRMATIVELY and score severity on its merits per the SEVERITY CALIBRATION section. A clearly visible crease is a "crease", not a "possible crease". A gap in the course is a "missing shingle", not a "possible anomaly".
- Use tentative words ("possible", "appears to", "may be") ONLY for genuinely borderline cases where you truly cannot tell. A genuinely borderline finding gets severity "minor", confidence "low", cause_origin "ambiguous".
- Image resolution alone is NOT a reason to downgrade a clear finding. A missing shingle and a tab crease are both visible in a normal wide roof photo — do not push them to "minor/ambiguous" by hiding behind "limited resolution".

When the visual indicator is real and describable, USE "moderate" and "severe" — do not default everything to minor.

============================================================
YOUR JOB: ACTIVELY FIND THE DAMAGE
============================================================

The damage is in the photo. Find it and commit to it. Do a systematic visual sweep of the entire roof surface, course by course, top to bottom, looking for the damage signatures below. Do NOT wait for chalk marks to tell you where to look — find the damage yourself.

When a damage signature is clearly visible, COMMIT. State it affirmatively. Do not write "possible", "appears to be", "may be", "warrants close-up to confirm", or "unresolvable at this scale" for damage that is visibly present in the image. An adjuster needs a definite finding, not a list of maybes. Save tentative language strictly for genuinely borderline cases.

SWEEP THE ROOF FOR THESE FOUR SIGNATURES:

1. MISSING SHINGLE / MISSING TAB — highest priority, and the easiest to see. Scan every course for a GAP in the regular pattern.
   WHAT IT LOOKS LIKE: a tab-sized area that is RECTANGULAR with DEFINED, SHARP EDGES, darker than the surrounding shingles because the tab is GONE and you are seeing the course beneath it, the dark underlayment, or the wood deck. It often sits slightly RECESSED — a step down — from the surrounding tabs, and the edges of the neighboring shingles frame it like a window. Its shape matches one tab's footprint and aligns to the course grid.
   CRITICAL — MISSING SHINGLE vs. GRANULE LOSS: a sharp-edged, tab-sized, rectangular dark zone is a MISSING SHINGLE. It is NOT "granular loss" and NOT "granule displacement". Granule loss is diffuse, gradual, and irregular in shape — it NEVER forms a clean tab-shaped rectangle with defined edges. If you find yourself describing "a dark rectangular zone the size of one tab with defined edges" or "a darker rectangular area localized to one tab" — STOP. That is a MISSING SHINGLE. Classify it as a missing shingle.
   A missing shingle is ALWAYS category "wind" and ALWAYS severity "severe". Label the finding TYPE exactly "Missing shingle" — never "granular loss", "granule displacement", "localized granule displacement", "dark zone", "dark exposure", or "discoloration". A missing shingle is one of the strongest claim items that exists; never miss one, never downgrade one, and never mislabel one as granule loss.

2. SHINGLE CREASE — a dark fold/bend line across the FACE of an individual tab (not the shadow line at the tab's bottom edge). Often runs horizontal or slightly diagonal across the mid-to-upper tab face, frequently with fractured or lighter granules along the fold. One clearly visible crease = MODERATE. Two or more creases on the same slope = SEVERE. A visible crease is a crease — do not call it "possible". Examine each horizontal line on a slope on its own — do not sweep every dark line into "course shadow" in one judgment. A course-overlap shadow runs continuously across the full width of the course at the very bottom edge of the tabs above it; a crease is confined to about one tab and sits up on the tab face above that bottom edge, often with a slight kink or granule disturbance. If a line clearly sits on a tab face rather than at a course bottom edge, it is a crease — report it even on a wide, full-slope photo. A crease sits on an intact tab that is still in place: if the dark lines are inside a tab-shaped gap where a tab is missing, those are the edges and shadow lines of the course exposed beneath — that is ONE missing shingle, not creases.

3. LIFTED / CURLED TAB — a tab corner or edge raised off the course below, casting its own shadow and breaking the flat plane of the slope. Moderate, or severe if the underside / daylight is visible.

4. HAIL IMPACT — circular bruise or dark spot with granule displacement in a random scatter pattern.

CHALK MARKS — a field inspector's chalk mark (any color; circle, tick, dash, line, X, or arrow) is a POINTER to damage, not damage itself. Inspectors mark on, just above, or beside a defect so the mark stays visible without covering it. The chalk mark is ink — it is NEVER a finding on its own, and it is never sealant or a repair smear. Each chalk mark points to exactly ONE defect: the single clearest defect in its immediate vicinity, almost always the shingle directly below or right beside the mark. Identify what that one defect actually is — missing tab, crease, lifted tab, or hail hit — and report it as ONE finding with confidence "high", because a professional already verified it on the roof. Do NOT also report the chalk mark's own location as a separate finding. Do NOT invent a crease or any other defect at the mark just because a mark is there. If you cannot resolve exactly what the marked defect is, still report only ONE finding for that mark. A chalk mark visible anywhere in the photo — including near an edge or corner of the frame — marks a real defect that is IN the photo, at or right beside the mark. Find that defect and report it as a finding. NEVER dismiss a visible chalk mark as pointing to something "outside the image", as "for reference only", or as "needing another photo": if the chalk is in frame, the defect it marks is in frame. Chalk marks are corroboration, not a prerequisite: still detect un-chalked damage on your own.

ONE DEFECT = ONE FINDING — DO NOT MULTIPLY. Report one finding per distinct physical defect you can actually see and point to. Never split a single defect into several findings, and never add a finding for a vague impression ("granules look disturbed nearby", "texture seems off") — that is not a separate defect. Before adding a second or third finding to a photo, confirm it is a genuinely separate defect on a different shingle, clearly visible in the image. If you are not certain a second item is real, leave it out and note it in adjuster_notes instead. A photo showing one chalk-marked defect should produce exactly ONE finding. Precision earns more carrier credibility than a long list.

============================================================
WIND DAMAGE — RIGOROUS IDENTIFICATION (CO-EQUAL TO HAIL)
============================================================

Wind damage is the second most contested call. Carriers love to call creased and lifted shingles "old" or "installation defect." It usually isn't — wind damage is covered, frequent, and dollar-for-dollar one of the strongest claim drivers because EACH creased or lifted shingle is a separate line-item replacement.

The single most important wind indicator is SHINGLE CREASING. Learn it — and do NOT confuse it with normal course shadow lines:

- A crease is a fold line on the EXPOSED FACE of an INDIVIDUAL tab, distinct from the natural shadow at the tab's bottom edge.
- It appears as a thin DARK CRACK, BEND LINE, or pinch mark on the FACE of the tab — not at the boundary between two tabs.
- A real crease often shows: (a) a fracture in the granule layer along the fold, (b) granules popped off along the fold line exposing the mat underneath, (c) a slight surface deformation visible as a height change.
- It is caused by wind lifting the tab up and back past its elastic limit, breaking the seal strip, and the shingle returning to a roughly flat position with a permanent bend.
- DO NOT call the natural horizontal shadow at the BOTTOM of each tab a crease. That shadow is the course overlap and appears on every healthy roof.
- DO NOT call the lateral seam between two adjacent tabs in the same course a crease.
- Multiple confirmed creases on adjacent tabs of the same course is a strong signal.
- A single faint dark line that runs cleanly along the bottom of every tab in a course IS the course overlap, NOT creasing.

Other strong wind indicators (ANY one is sufficient for "wind" classification):
- Lifted or curled tab corners (clean upward lift, not heat curl)
- Missing tabs or shingles with clean break edges (not crumbling)
- Sealant strip exposed or pulled apart (visible black asphalt bead with no contact)
- Exposed nail heads from shingle lift
- Tabs displaced laterally or out of alignment with neighbors
- Granule loss along the bend line of a crease (granules pop off the fold)
- Debris impact marks (branch strikes, scuffs from blown debris)
- Directional granule streaks along slope grain

When you see chalk marks on a slope and the area looks "fine" — look again specifically for a dark horizontal line across the top of those tabs. That is almost certainly what was marked.

============================================================
SEVERITY CALIBRATION — THIS IS HOW YOU ASSIGN SEVERE / MODERATE / MINOR
============================================================

Severity is the most-misused field in your output. Calibrate it correctly:

**SEVERE** — Use for any of:
- Missing shingle or missing tab (any cause — wind is the default attribution unless clearly torn off by a tree branch etc.)
- Displaced shingle out of its course position
- Visible torn mat or large exposed mat fracture
- Two or more creased tabs visible on the same slope in the same photo
- Lifted tab where the underside is visible (clear daylight under the tab)
- A creased tab co-located with mat exposure or granule loss along the crease line
- Any structural breach (puncture through the deck visible)

**MODERATE** — Use for any of:
- A single clearly visible crease on a single tab (dark fold line on the exposed tab face, not the bottom-edge course shadow)
- A single clearly visible hail bruise with mat fracture and granule halo
- Confirmed lifted tab corner without daylight underneath
- A chalk-marked tab where you can also visually identify the damage indicator the inspector marked

**MINOR** — Use for any of:
- Granule displacement at one edge of one tab with no fracture
- Surface scuff or directional streak
- A chalk-marked area where you can see SOMETHING is off but cannot resolve the exact indicator

**NONE / NO FINDING** — Use when no specific damage is visible.

CRITICAL: A creased shingle is FAILED. The seal strip is broken, the tab is no longer wind-resistant, and water can intrude. Do NOT call a clearly visible crease "minor." A single confirmed crease is MODERATE. Two or more confirmed creases on the same slope is SEVERE.

A missing shingle/tab is ALWAYS at least MODERATE and almost always SEVERE. It is also WIND damage (category: "wind"), not "OTHER", unless there is specific reason to attribute it elsewhere.

============================================================
BOUNDING BOX — DRAW IT ON THE DAMAGE
============================================================

The "bbox" field must cover the DAMAGED SHINGLE itself — the tab with the crease, the missing piece, the impact halo. The bbox is NOT placed on:
- A chalk mark near the damage (move the bbox to the actual damaged tab)
- A general area where you "think" damage might be (move the bbox to the specific indicator)
- A wide region around the damage (tighten the bbox to the affected tab)

If you cannot place a tight bbox on a specific damaged tab, you do not have a finding. Return findings: [] or fewer findings.

============================================================
HAIL DAMAGE — RIGOROUS IDENTIFICATION
============================================================

The most contested call in roofing claims is hail vs. age. Carriers default to "age." You default to documenting hail when the indicators support it.

Any ONE of these is a STRONG hail indicator (sufficient for "hail" classification):
- Circular bruise or depression, roughly 1/4" to 2" diameter
- Random scatter pattern (not linear, not clustered at edges, not aligned with foot traffic)
- Fractured asphalt mat visible at impact point (exposed black mat, sharp/clean edge)
- Granule displacement localized to a single circular spot, with surrounding granules intact
- Fresh, dark exposed mat with no oxidation (recent damage, not weathered)
- Multiple impacts of consistent diameter on the same slope (storms produce hailstones of similar size)
- Soft "bruise" feel inferable from the image (slight mat depression even when granules remain)
- Damage to soft metals on the roof (vents, gutters, flashing, A/C condenser fins, mailbox) — these corroborate hail on the shingles

Hail on asphalt shingles often shows as a halo: a center spot where the mat is fractured, surrounded by a ring where granules are displaced. Look for this signature.

============================================================
HAIL ON CLOSE-UP PHOTOS — COMMIT TO THE FINDING
============================================================

A close-up shingle photo is taken for ONE reason: the field adjuster already sees a hail hit and wants it documented. On a tight close-up framed on a shingle, COMMIT to the finding. Do not return "no damage" on a tight close-up unless the shingle is genuinely clean.

A hail bruise does NOT always look like a dark exposed-mat crater. It very commonly appears as:
- A LIGHTER circular spot — the impact knocked colored granules loose and exposed the paler granule layer beneath, or scuffed the surface lighter
- A circular spot of DISTURBED TEXTURE — granules pocked, scuffed, crushed, or shoved aside — even when the color barely differs from the shingle around it
- A soft round depression that catches light differently from the flat shingle surface
- A self-contained round spot roughly 1/4" to 1.5" across, with the shingle immediately around it untouched

TEXTURE is the proof, not color. If granules inside a discrete round area look scuffed, pocked, crushed, or displaced, that is a hail impact — whether the spot is lighter OR darker than its surroundings.

PROHIBITED DISMISSALS. For a discrete, roughly circular spot you must NOT explain it away as "sunlight reflection," "sun differential," "glare," "shadow," "uneven lighting," or "camera flash." Sunlight and shadow fall across a roof in broad gradients with soft edges — they physically cannot create a single isolated round spot a couple of inches wide surrounded by normal shingle. A discrete circular spot was made by an impact, not by light. Classify it as hail.

The ONLY innocent explanation for a discrete round spot is a manufacturer color-granule blend — but a color blend has the SAME smooth, intact granule texture as the rest of the shingle; only the color differs. If the texture inside the spot is disturbed, it is hail, not a blend. When a close-up is genuinely ambiguous, classify it as hail and document the indicators in adjuster_notes.

============================================================
GRANULAR LOSS — DIFFERENTIAL DIAGNOSIS
============================================================

Granular loss can come from three sources. Classify by PATTERN, not by amount:

1. HAIL granular loss → LOCALIZED. Bare spots are circular or irregular but discrete, with hard edges. Surrounding shingle is intact. Often paired with mat damage at the center. → Classify as "hail".

2. WIND granular loss → DIRECTIONAL. Streaks running with slope grain, along worn pathways, or clustered at lifted tab edges. Often paired with sealant failure or tab creases. → Classify as "wind".

3. UV/AGE granular loss → UNIFORM. Continuous gradient of loss across the entire slope (most pronounced on south or west faces), with oxidized shingle edges, curling, and/or alligator cracking VISIBLY present in the same area. → Classify as "wear_tear" ONLY when uniformity is clearly the dominant pattern AND aging signs are co-present.

When the same slope shows BOTH localized impacts AND broader granule thinning: classify the localized impacts as "hail" and mention the underlying condition in adjuster_notes. Do not let general roof age absorb specific storm damage findings.

============================================================
OTHER CATEGORIES
============================================================

"defect" — manufacturing issues: blistering (raised bumps from gas pockets), thermal splitting in straight lines, premature delamination, factory edge defects. Note: usually warranty, not insurance.

"other" — flashing failures, vent boot cracks, ridge cap displacement, exposed underlayment, pipe penetration issues, gutter damage.

============================================================
CAUSE / ORIGIN
============================================================

For each finding, set "cause_origin":
- "storm-related" — evidence supports a storm peril (hail, wind)
- "non-storm" — clear evidence of age, defect, or installer error
- "ambiguous" — genuinely unclear; describe both possibilities

Bias: when evidence is ambiguous, prefer "ambiguous" over "non-storm". Carriers can challenge ambiguous findings, but they cannot blanket-deny them.

============================================================
HAIL / WIND CONFIDENCE & CLAIM STRENGTH
============================================================

You will return three top-level fields:

"hail_confidence":
- "high" — clear circular impacts, fresh mat exposure, random distribution
- "medium" — some indicators (e.g. localized granule loss in circular pattern) but missing fresh mat exposure or clear bruise
- "low" — granule loss only, ambiguous pattern, single suspect spot
- "none" — no hail indicators at all

"wind_confidence":
- "high" — clear shingle creasing (dark horizontal line on tab), lifted/missing tabs, broken seal strip, or multiple of these on adjacent tabs
- "medium" — possible creasing or lifted tab visible but not definitive; one suspect tab; granule displacement at tab edges
- "low" — minor edge granule loss, slightly raised tab, no clear crease or lift line
- "none" — no wind indicators

"claim_strength":
- "strong" — multiple unambiguous storm-related findings of moderate or severe severity with specific cited visual indicators; OR one severe finding (missing shingle, displaced shingle, clear mat fracture) with corroborating context.
- "moderate" — one clearly documented storm-related finding with unambiguous visual evidence.
- "weak" — only ambiguous, "probable", or minor findings — supports further investigation but not a confident claim alone.
- "no-claim" — no storm-related findings visible. This is the CORRECT answer for a roof in normal condition. Do not manufacture findings to avoid "no-claim".

Pair these honestly. A roof with NO visible damage should return "no-claim" and findings: []. Do not invent damage to be helpful. Equally, do not downgrade clear unambiguous damage just to be conservative.

============================================================
EVIDENCE CITATION
============================================================

For every finding, include an "evidence" field: 1-2 sentences citing the SPECIFIC visual indicator that justifies the category. Example: "Granules displaced in a 1-inch circular pattern with fresh black mat exposed at center; matching impacts on adjacent shingles." This is what the adjuster cites to the carrier. Be specific.

If you classify something as "wear_tear" or "defect" or "non-storm", you must explain WHY in the evidence field — what rules out storm cause. "Uniform oxidation across the slope with no localized impact pattern" is acceptable. "Looks old" is not.

============================================================
OUTPUT — STRICT JSON, NO MARKDOWN FENCES
============================================================

{
  "is_roof": true | false,
  "not_roof_reason": "string if is_roof is false",
  "overall_severity": "severe" | "moderate" | "minor" | "none",
  "roof_material": "asphalt shingle" | "metal" | "tile" | "flat/membrane" | "unknown",
  "image_quality": "good" | "fair" | "poor",
  "image_quality_note": "string if not good",
  "summary": "1-2 sentence plain-language summary that leads with cause/origin",
  "test_square_assessment": "1-2 sentences about hit density. Empty string if no test square.",
  "damage_categories_present": ["hail" | "wind" | "granular_loss" | "wear_tear" | "defect" | "other"],
  "hail_confidence": "high" | "medium" | "low" | "none",
  "wind_confidence": "high" | "medium" | "low" | "none",
  "claim_strength": "strong" | "moderate" | "weak" | "no-claim",
  "findings": [
    {
      "id": "F1",
      "category": "hail" | "wind" | "granular_loss" | "wear_tear" | "defect" | "other",
      "cause_origin": "storm-related" | "non-storm" | "ambiguous",
      "type": "specific type (e.g. 'Circular hail impact with mat fracture')",
      "severity": "severe" | "moderate" | "minor",
      "description": "2-3 sentences. Lead with what you see, then what it means for the claim.",
      "evidence": "1-2 sentences citing the specific visual indicator that justifies this category. The line the adjuster quotes to the carrier.",
      "bbox": { "x": 0-100, "y": 0-100, "w": 0-100, "h": 0-100 }
    }
  ],
  "adjuster_notes": "3-5 sentence narrative for the claim file. Lead with cause/origin determination. State the case for coverage affirmatively. If matching slopes are affected by the same storm, note it. Reference Florida/state-specific considerations where relevant (matching statute, recent reforms)."
}

If the image is not a roof at all: set is_roof: false, not_roof_reason describing what the image shows, findings: [], damage_categories_present: [], overall_severity: "none", hail_confidence: "none", wind_confidence: "none", claim_strength: "no-claim", adjuster_notes: "".

If the roof is in normal condition with no specific damage indicators visible: set findings: [], damage_categories_present: [], overall_severity: "none", hail_confidence: "none", wind_confidence: "none", claim_strength: "no-claim", and write a brief honest adjuster_notes (e.g. "No storm-related findings on this slope. Roof presents in normal condition."). This is a valid and expected output — many roof photos show healthy roofs.`;
}

// ============ Boot ============
async function boot() {
  try {
    await ensureSchema();
    try { await q("CREATE TABLE IF NOT EXISTS orgs (id SERIAL PRIMARY KEY, name TEXT NOT NULL, owner_user_id INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())"); } catch (e) { console.error('[boot] orgs table', e.message); }
    try { await q("CREATE TABLE IF NOT EXISTS org_invites (id SERIAL PRIMARY KEY, org_id INTEGER NOT NULL, code TEXT UNIQUE NOT NULL, label TEXT, created_by INTEGER, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), used_by INTEGER, used_at TIMESTAMPTZ, revoked BOOLEAN NOT NULL DEFAULT false)"); } catch (e) { console.error('[boot] org_invites table', e.message); }
    try { await q("ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id INTEGER"); } catch (e) {}
    try { await q("ALTER TABLE users ADD COLUMN IF NOT EXISTS org_role TEXT"); } catch (e) {}
    try { await q("ALTER TABLE users ADD COLUMN IF NOT NULL DEFAULT true"); } catch (e) {}
    try { await q("ALTER TABLE org_invites ADD COLUMN IF NOT EXISTS email TEXT"); } catch (e) {}
    try { await q("CREATE TABLE IF NOT EXISTS events (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, org_id INTEGER, claim_local_id TEXT, title TEXT NOT NULL, description TEXT, starts_at TIMESTAMPTZ NOT NULL, ends_at TIMESTAMPTZ, all_day BOOLEAN NOT NULL DEFAULT false, location TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"); } catch (e) { console.error('[boot] events table', e.message); }
    try { await q("CREATE INDEX IF NOT EXISTS events_user_idx ON events (user_id, starts_at)"); } catch (e) {}
    try { await q("CREATE INDEX IF NOT EXISTS events_org_idx ON events (org_id, starts_at)"); } catch (e) {}
    try { await q("CREATE TABLE IF NOT EXISTS leads (id SERIAL PRIMARY KEY, org_id INTEGER, name TEXT NOT NULL, email TEXT, phone TEXT, address TEXT, carrier TEXT, claim_number TEXT, source TEXT, notes TEXT, assigned_to INTEGER, assigned_at TIMESTAMPTZ, assigned_by INTEGER, status TEXT NOT NULL DEFAULT 'new', converted_claim_local_id TEXT, converted_at TIMESTAMPTZ, converted_by INTEGER, created_by INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"); } catch (e) { console.error('[boot] leads table', e.message); }
    try { await q("CREATE INDEX IF NOT EXISTS leads_org_idx ON leads (org_id, status, created_at DESC)"); } catch (e) {}
    try { await q("CREATE INDEX IF NOT EXISTS leads_assigned_idx ON leads (assigned_to, status)"); } catch (e) {}
    try { await q("CREATE TABLE IF NOT EXISTS team_jobs (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, org_id INTEGER, claim_local_id TEXT NOT NULL, name TEXT, address TEXT, insured TEXT, insured_email TEXT, carrier TEXT, claim_number TEXT, stage TEXT, has_damage BOOLEAN, contract_status TEXT, finalized BOOLEAN, photos_count INTEGER, last_touched TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"); } catch (e) { console.error('[boot] team_jobs table', e.message); }
    try { await q("CREATE UNIQUE INDEX IF NOT EXISTS team_jobs_user_claim ON team_jobs (user_id, claim_local_id)"); } catch (e) {}
    try { await q("CREATE INDEX IF NOT EXISTS team_jobs_org_idx ON team_jobs (org_id)"); } catch (e) {}
    try { await q("CREATE TABLE IF NOT EXISTS cloud_jobs (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, job_id TEXT NOT NULL, name TEXT, payload TEXT, size_bytes INTEGER, updated_at TIMESTAMPTZ DEFAULT now())"); } catch (e) { console.error("[schema] cloud_jobs", e); }

// ============ Google OAuth + Gmail + Calendar ============
// One-time schema extension for the users table to hold Google OAuth tokens.
(async () => {
  try {
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_access_token TEXT");
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_refresh_token TEXT");
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_token_expiry BIGINT");
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_email TEXT");
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_scopes TEXT");
    console.log('[google] users table extended for Google tokens');
  } catch (e) {
    console.error('[google schema]', e && e.message);
  }
})();

const GOOGLE_OAUTH_CLIENT_ID = (process.env.GOOGLE_OAUTH_CLIENT_ID || '').trim();
const GOOGLE_OAUTH_CLIENT_SECRET = (process.env.GOOGLE_OAUTH_CLIENT_SECRET || '').trim();
const GOOGLE_OAUTH_REDIRECT_URI = (process.env.GOOGLE_OAUTH_REDIRECT_URI ||
  'https://hailgrade-backend.onrender.com/auth/google/callback').trim();
const GOOGLE_OAUTH_SCOPES = [
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/calendar',
];
const GOOGLE_OAUTH_FRONTEND_RETURN = (process.env.GOOGLE_OAUTH_FRONTEND_RETURN ||
  'https://ampleclaim.com').trim();

// In-memory state map for CSRF protection on the OAuth dance. Single-instance only.
// Each entry expires 10 minutes after creation.
const _googleStates = new Map();
function _makeGoogleState(uid) {
  const s = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) +
            Math.random().toString(36).slice(2);
  _googleStates.set(s, { userId: uid, expires: Date.now() + 10 * 60 * 1000 });
  // Garbage-collect expired entries opportunistically
  for (const [k, v] of _googleStates.entries()) {
    if (v.expires < Date.now()) _googleStates.delete(k);
  }
  return s;
}
function _consumeGoogleState(s) {
  const e = _googleStates.get(s);
  if (!e) return null;
  _googleStates.delete(s);
  if (e.expires < Date.now()) return null;
  return { id: e.userId };
}

// Returns a valid access token for this user. Refreshes if expired.
async function googleAccessToken(userId) {
  const ur = await pool.query(
    "SELECT google_access_token, google_refresh_token, google_token_expiry FROM users WHERE id = $1",
    [userId]
  );
  if (!ur.rowCount) throw new Error('user not found');
  let { google_access_token: accessToken,
        google_refresh_token: refreshToken,
        google_token_expiry: expiry } = ur.rows[0];
  if (!refreshToken) throw new Error('Google account not connected');
  // Reuse current token if it still has 60+ seconds left
  if (accessToken && expiry && (Number(expiry) - 60000) > Date.now()) return accessToken;
  // Otherwise refresh
  const refRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GOOGLE_OAUTH_CLIENT_ID,
      client_secret: GOOGLE_OAUTH_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  });
  const td = await refRes.json();
  if (!refRes.ok) throw new Error('refresh failed: ' + JSON.stringify(td).slice(0, 200));
  accessToken = td.access_token;
  const newExpiry = Date.now() + (td.expires_in || 3500) * 1000;
  await pool.query(
    "UPDATE users SET google_access_token = $1, google_token_expiry = $2 WHERE id = $3",
    [accessToken, newExpiry, userId]
  );
  return accessToken;
}

// Start the OAuth flow. Frontend hits this with the user's session token,
// gets back a URL, and redirects the user to it.
app.get('/auth/google/connect', requireAuth, (req, res) => {
  if (!GOOGLE_OAUTH_CLIENT_ID || !GOOGLE_OAUTH_CLIENT_SECRET) {
    return res.status(503).json({ error: 'Google OAuth not configured on this server' });
  }
  const state = _makeGoogleState(req.user.id);
  const params = new URLSearchParams({
    client_id: GOOGLE_OAUTH_CLIENT_ID,
    redirect_uri: GOOGLE_OAUTH_REDIRECT_URI,
    response_type: 'code',
    scope: GOOGLE_OAUTH_SCOPES.join(' '),
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'true',
    state: state
  });
  return res.json({ url: 'https://accounts.google.com/o/oauth2/v2/auth?' + params.toString() });
});

// Google redirects back here with ?code=... &state=...
app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    const back = (status, reason) =>
      res.redirect(GOOGLE_OAUTH_FRONTEND_RETURN + '/?google=' + status +
        (reason ? '&reason=' + encodeURIComponent(String(reason)) : ''));
    if (error) return back('error', error);
    if (!code || !state) return res.status(400).send('Missing code or state');
    const dec = _consumeGoogleState(String(state));
    if (!dec) return back('error', 'invalid_state');
    const userId = dec.id;

    // Exchange the code for tokens
    const tokRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: String(code),
        client_id: GOOGLE_OAUTH_CLIENT_ID,
        client_secret: GOOGLE_OAUTH_CLIENT_SECRET,
        redirect_uri: GOOGLE_OAUTH_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const td = await tokRes.json();
    if (!tokRes.ok) {
      console.error('[google callback]', td);
      return back('error', 'token_exchange');
    }

    // Get the Gmail address the user authorized
    let email = null;
    try {
      if (td.id_token) {
        const parts = td.id_token.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
          email = payload.email || null;
        }
      }
    } catch (e) { /* ignore */ }
    if (!email && td.access_token) {
      try {
        const ui = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { 'Authorization': 'Bearer ' + td.access_token }
        });
        const uid = await ui.json();
        email = uid.email || null;
      } catch (e) { /* ignore */ }
    }

    const expiry = Date.now() + (td.expires_in || 3500) * 1000;
    await pool.query(
      "UPDATE users SET google_access_token = $1, " +
      "google_refresh_token = COALESCE($2, google_refresh_token), " +
      "google_token_expiry = $3, google_email = $4, google_scopes = $5 WHERE id = $6",
      [td.access_token, td.refresh_token || null, expiry, email, td.scope || null, userId]
    );

    return back('ok', email || '');
  } catch (e) {
    console.error('[google callback]', e);
    return res.status(500).send('Callback failed: ' + String(e && e.message || e).slice(0, 200));
  }
});

// Is the current user connected? Used by frontend to show the Connect/Disconnect button.
app.get('/me/google', requireAuth, async (req, res) => {
  const r = await pool.query(
    "SELECT google_email, (google_refresh_token IS NOT NULL) AS connected FROM users WHERE id = $1",
    [req.user.id]
  );
  if (!r.rowCount) return res.json({ connected: false });
  return res.json({
    connected: !!r.rows[0].connected,
    email: r.rows[0].google_email || null
  });
});

// Disconnect — clears all Google tokens for the user.
app.delete('/me/google', requireAuth, async (req, res) => {
  await pool.query(
    "UPDATE users SET google_access_token = NULL, google_refresh_token = NULL, " +
    "google_token_expiry = NULL, google_email = NULL, google_scopes = NULL WHERE id = $1",
    [req.user.id]
  );
  return res.json({ ok: true });
});

// Gmail search. Accepts either ?q=<raw_gmail_query> or a set of claim fields
// (name, address, email, claim_number) and constructs an OR query from them.
app.get('/gmail/search', requireAuth, async (req, res) => {
  try {
    const token = await googleAccessToken(req.user.id);
    let q = String(req.query.q || '').trim();
    if (!q) {
      const parts = [];
      const esc = (s) => '"' + String(s).replace(/"/g, '') + '"';
      if (req.query.name)         parts.push(esc(req.query.name));
      if (req.query.address)      parts.push(esc(req.query.address));
      if (req.query.email)        parts.push('from:' + String(req.query.email));
      if (req.query.claim_number) parts.push(esc(req.query.claim_number));
      q = parts.join(' OR ');
    }
    if (!q) return res.json({ messages: [], query: '' });

    const max = Math.min(parseInt(req.query.max) || 20, 50);
    const listRes = await fetch(
      'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=' +
      encodeURIComponent(q) + '&maxResults=' + max,
      { headers: { 'Authorization': 'Bearer ' + token } }
    );
    const listData = await listRes.json();
    if (!listRes.ok) return res.status(500).json({ error: 'gmail list failed', detail: listData });

    const messages = [];
    for (const m of (listData.messages || []).slice(0, max)) {
      try {
        const r = await fetch(
          'https://gmail.googleapis.com/gmail/v1/users/me/messages/' + m.id +
          '?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject&metadataHeaders=Date',
          { headers: { 'Authorization': 'Bearer ' + token } }
        );
        const md = await r.json();
        const headers = {};
        ((md.payload && md.payload.headers) || []).forEach(h => { headers[h.name] = h.value; });
        messages.push({
          id: m.id,
          threadId: m.threadId,
          snippet: md.snippet || '',
          from: headers.From || '',
          to: headers.To || '',
          subject: headers.Subject || '',
          date: headers.Date || '',
          labelIds: md.labelIds || []
        });
      } catch (e) { /* skip this message */ }
    }
    return res.json({ query: q, count: messages.length, messages });
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e).slice(0, 200) });
  }
});

// Calendar — list events on the primary calendar.
app.get('/calendar/events', requireAuth, async (req, res) => {
  try {
    const token = await googleAccessToken(req.user.id);
    const timeMin = req.query.timeMin || new Date().toISOString();
    const timeMax = req.query.timeMax ||
      new Date(Date.now() + 60 * 86400000).toISOString();
    const url = 'https://www.googleapis.com/calendar/v3/calendars/primary/events?' +
      new URLSearchParams({
        timeMin, timeMax,
        singleEvents: 'true',
        orderBy: 'startTime',
        maxResults: String(Math.min(parseInt(req.query.maxResults) || 50, 250))
      }).toString();
    const r = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token } });
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'calendar list failed', detail: data });
    return res.json({ events: data.items || [] });
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e).slice(0, 200) });
  }
});

// Calendar — create an event.
app.post('/calendar/events', requireAuth, async (req, res) => {
  try {
    const token = await googleAccessToken(req.user.id);
    const r = await fetch(
      'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body || {})
      }
    );
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'calendar create failed', detail: data });
    return res.json({ event: data });
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e).slice(0, 200) });
  }
});

// Calendar — update an event.
app.patch('/calendar/events/:id', requireAuth, async (req, res) => {
  try {
    const token = await googleAccessToken(req.user.id);
    const r = await fetch(
      'https://www.googleapis.com/calendar/v3/calendars/primary/events/' +
      encodeURIComponent(req.params.id),
      {
        method: 'PATCH',
        headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body || {})
      }
    );
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'calendar update failed', detail: data });
    return res.json({ event: data });
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e).slice(0, 200) });
  }
});

// Calendar — delete an event.
app.delete('/calendar/events/:id', requireAuth, async (req, res) => {
  try {
    const token = await googleAccessToken(req.user.id);
    const r = await fetch(
      'https://www.googleapis.com/calendar/v3/calendars/primary/events/' +
      encodeURIComponent(req.params.id),
      { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + token } }
    );
    if (!r.ok && r.status !== 204) {
      const data = await r.json().catch(() => ({}));
      return res.status(500).json({ error: 'calendar delete failed', detail: data });
// DEBUG: dump all registered Express routes
console.log('[routes-dump] start');
let _rcount = 0;
app._router.stack.forEach((m) => {
  if (m.route) {
    const methods = Object.keys(m.route.methods).join(',').toUpperCase();
    console.log('  ' + methods + ' ' + m.route.path);
    _rcount++;
  }
});
console.log('[routes-dump] total: ' + _rcount);

// Smoke test endpoint added at very bottom to verify late-bound routes work
app.get('/zz-smoke', (req, res) => res.json({ ok: true, ts: Date.now() }));

    app.listen(port, () => {
      console.log(`[boot] HailGrade API listening on :${port}`);
    });
  } catch (err) {
    console.error('[boot] failed', err);
    process.exit(1);
  }
}

boot();
