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
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin_only' });
  }
  next();
}

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
        max_tokens: 2500,
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

  return `You are a roof damage analyst trained to support both public adjusters and roofing contractors. You're examining a roof image for an insurance claim. Photo slope: ${slope || 'unknown'}.${contextNote}${testNote}

Your single most important job: distinguish covered storm damage from non-covered conditions. Insurers routinely deny claims by misclassifying hail or wind damage as wear and tear. Be precise.

DAMAGE CATEGORIES — classify every finding into exactly one:
1. "hail" — Impact damage from hail. Tells: circular bruising (round depressions 1/2"-2"), random distribution across slope, fractured shingle mat, soft spots, granule displacement at the impact point, fresh mat exposure with no oxidation. NOT linear, NOT clustered along edges.
2. "wind" — Damage from wind events. Tells: creased shingles, lifted/curled tabs, missing tabs with clean break edges, sealant strip failure, exposed nail heads from shingle lift, debris impacts.
3. "granular_loss" — Loss of granules from the shingle surface. Distinguish source: IF distributed with circular impact patterns → likely hail (category should still be "hail" with granular loss as the mechanism). IF uniform across slope, especially on south-facing slopes → likely UV/age (category "wear_tear"). Use "granular_loss" category ONLY for storm-caused granule loss that doesn't clearly fit "hail".
4. "wear_tear" — Age-related deterioration. Tells: uniform granule loss without impact pattern, alligator cracking, curling tab corners, fastener corrosion, moss/algae staining, oxidized shingle edges, brittle mat. NOT a covered peril — but document it so insurers can't blanket-deny.
5. "defect" — Manufacturing defect. Tells: blistering, thermal splitting in straight lines, premature shingle delamination, factory edge defects. Often warranty-eligible.
6. "other" — Flashing failures, vent boot cracks, ridge cap issues, exposed underlayment.

CAUSE-ORIGIN — for each finding, also indicate "storm-related", "non-storm", or "ambiguous".

Return ONLY valid JSON, no markdown fences. Schema:
{
  "is_roof": true|false,
  "not_roof_reason": "...",
  "overall_severity": "severe"|"moderate"|"minor"|"none",
  "roof_material": "asphalt shingle"|"metal"|"tile"|"flat/membrane"|"unknown",
  "image_quality": "good"|"fair"|"poor",
  "image_quality_note": "...",
  "summary": "...",
  "test_square_assessment": "...",
  "damage_categories_present": ["hail"|"wind"|"granular_loss"|"wear_tear"|"defect"|"other"],
  "findings": [{
    "id": "F1",
    "category": "hail"|"wind"|"granular_loss"|"wear_tear"|"defect"|"other",
    "cause_origin": "storm-related"|"non-storm"|"ambiguous",
    "type": "...",
    "severity": "severe"|"moderate"|"minor",
    "description": "...",
    "bbox": {"x":0-100, "y":0-100, "w":0-100, "h":0-100}
  }],
  "adjuster_notes": "..."
}

If the image is not a roof, set is_roof: false, not_roof_reason, findings: [], damage_categories_present: [], overall_severity: "none", adjuster_notes: "".`;
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
