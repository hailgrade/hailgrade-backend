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
app.use(express.json({ limit: '25mb' })); // 25mb so phone-quality JPEGs fit

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
      monthly_analyses_used: u.monthly_analyses_used
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
  const { image, media_type, slope, context = {}, photo_local_id, claim_local_id } = req.body || {};
  if (!image || !media_type) return res.status(400).json({ error: 'image_required' });

  // Soft monthly quota check (avoid runaway costs from a single user)
  const u = req.user;
  const quota = u.plan === 'firm' ? 2500 : 600;  // generous; tighten later
  if (u.monthly_analyses_used >= quota) {
    return res.status(429).json({ error: 'quota_exceeded', message: `Monthly quota of ${quota} analyses hit. Resets on ${u.monthly_analyses_reset_at}.` });
  }

  const prompt = buildAnalysisPrompt({ slope, ...context });

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
  _contractsSchemaReady = true;
}
function dsAuthHeader() {
  return "Basic " + Buffer.from(DS_API_KEY + ":").toString("base64");
}
function dsRowsOf(r) { return Array.isArray(r) ? r : (r && r.rows ? r.rows : []); }

app.post("/contracts/template", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    const body = req.body || {};
    if (!body.pdf_base64) return res.status(400).json({ error: "Missing contract file" });
    const clean = String(body.pdf_base64).replace(/^data:[^,]*,/, "");
    const fn = body.filename || "contract.pdf";
    await q("INSERT INTO user_contracts (user_id, filename, pdf_base64, uploaded_at) VALUES ($1,$2,$3, now()) ON CONFLICT (user_id) DO UPDATE SET filename=$2, pdf_base64=$3, uploaded_at=now()", [req.user.id, fn, clean]);
    res.json({ ok: true, filename: fn });
  } catch (e) {
    console.error("[contracts/template]", e);
    res.status(500).json({ error: "Could not save contract" });
  }
});

app.get("/contracts/template", requireAuth, async (req, res) => {
  try {
    await ensureContractsSchema();
    const rows = dsRowsOf(await q("SELECT filename, uploaded_at FROM user_contracts WHERE user_id=$1", [req.user.id]));
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
    const tpl = dsRowsOf(await q("SELECT filename, pdf_base64 FROM user_contracts WHERE user_id=$1", [req.user.id]));
    if (!tpl.length) return res.status(400).json({ error: "Upload your contract first" });
    const pdfBuf = Buffer.from(tpl[0].pdf_base64, "base64");
    const form = new FormData();
    const claimName = body.claim_name || "";
    form.append("title", "Roofing Agreement" + (claimName ? " - " + claimName : ""));
    form.append("subject", "Please sign your roofing agreement");
    form.append("message", "Please review and sign your roofing agreement. A signed copy will be emailed to all parties once complete.");
    form.append("signers[0][name]", signerName);
    form.append("signers[0][email_address]", signerEmail);
    form.append("signers[0][order]", "0");
    form.append("cc_email_addresses[0]", req.user.email);
    form.append("test_mode", "1");
    form.append("file[0]", new Blob([pdfBuf], { type: "application/pdf" }), tpl[0].filename || "contract.pdf");
    const dsRes = await fetch(DS_BASE + "/signature_request/send", { method: "POST", headers: { "Authorization": dsAuthHeader() }, body: form });
    const dsJson = await dsRes.json().catch(() => ({}));
    if (!dsRes.ok) {
      console.error("[contracts/send] provider error", dsRes.status, JSON.stringify(dsJson));
      const msg = (dsJson && dsJson.error && dsJson.error.error_msg) || "E-signature provider rejected the request";
      return res.status(502).json({ error: msg });
    }
    const sr = dsJson.signature_request || {};
    const srId = sr.signature_request_id || "";
    const ins = dsRowsOf(await q("INSERT INTO contracts (user_id, claim_local_id, claim_name, signer_name, signer_email, signature_request_id, status) VALUES ($1,$2,$3,$4,$5,$6,'sent') RETURNING id", [req.user.id, body.claim_local_id || null, claimName || null, signerName, signerEmail, srId]));
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
    const rows = dsRowsOf(await q("SELECT filename, pdf_base64, uploaded_at FROM user_contracts WHERE user_id=$1", [req.user.id]));
    if (!rows.length) return res.status(404).json({ error: "No contract on file" });
    res.json({ filename: rows[0].filename, pdf_base64: rows[0].pdf_base64, uploaded_at: rows[0].uploaded_at });
  } catch (e) {
    console.error("[contracts/template/file]", e);
    res.status(500).json({ error: "Could not load contract file" });
  }
});

/* =================== END CONTRACTS / E-SIGNATURE =================== */

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
    app.listen(port, () => {
      console.log(`[boot] HailGrade API listening on :${port}`);
    });
  } catch (err) {
    console.error('[boot] failed', err);
    process.exit(1);
  }
}

boot();
