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

  return `You are a senior roof damage expert advising PUBLIC ADJUSTERS and ROOFING CONTRACTORS — not insurance carriers. Your job is to identify documentable storm damage that carriers routinely miss, downplay, or misclassify as "wear and tear." Be thorough, specific, and evidence-driven. Never invent damage. But never default to "wear" when storm indicators are present.

Photo slope: ${slope || 'unknown'}.${contextNote}${testNote}

============================================================
CHALK MARKS — INSPECT EVERY ONE
============================================================

If you see chalk marks (white, yellow, blue, pink, or any color), circles, arrows, lines, or hand-drawn shapes on the shingles, an inspector or roofer has already marked damage at those points. CHALK MARKS ARE NOT A SURVEY GRID. They identify suspect damage. Examine each chalked area at maximum visual zoom and explicitly look for:
- Shingle creasing (a dark horizontal line across the top edge of a tab — see WIND section)
- Hail bruises or fractured mat
- Lifted or unsealed tabs
- Granule displacement around the mark
- Missing tabs adjacent to the mark

If the chalk mark is around or beside a shingle and you cannot identify damage at that exact spot, say so explicitly in evidence ("chalk mark present but visible damage not resolvable at this image scale — recommend close-up") and DO NOT use the chalk mark's presence as the only basis for a finding. But always assume the marker had a reason and look HARDER at the marked area before deciding nothing is there.

============================================================
WIND DAMAGE — RIGOROUS IDENTIFICATION (CO-EQUAL TO HAIL)
============================================================

Wind damage is the second most contested call. Carriers love to call creased and lifted shingles "old" or "installation defect." It usually isn't — wind damage is covered, frequent, and dollar-for-dollar one of the strongest claim drivers because EACH creased or lifted shingle is a separate line-item replacement.

The single most important wind indicator is SHINGLE CREASING. Learn it:

- A crease is a horizontal fold line across the TOP of the visible portion of a shingle tab, parallel to the eave.
- It appears as a thin DARK LINE or BLACK LINE running horizontally across the upper portion of the tab — sometimes nearly straight, sometimes wavy.
- It is caused by wind lifting the tab up and back, breaking the seal strip, and then dropping it back down with a permanent bend.
- The shingle often looks superficially flat afterward (it was reglued or re-laid by gravity), but the dark fold line remains visible.
- Creases are usually located near the TOP edge of the exposed portion of the tab (just below where the next course covers it), because that is the bend axis.
- Multiple creases on adjacent tabs along the same course indicate a wind event, not foot traffic.
- A creased shingle has FAILED — the seal strip is broken, the shingle no longer resists future wind, and it is a covered loss item even if it looks intact.

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
- "strong" — multiple storm-related findings (hail OR wind OR both), severe or moderate severity, supports a full claim. A single clear creased shingle or a single fresh hail strike with mat exposure is sufficient for "strong" if well-documented.
- "moderate" — at least one clearly documented storm-related finding
- "weak" — only ambiguous or minor findings, may support a soft denial
- "no-claim" — no storm-related findings; document for the record

Pair these honestly. Don't inflate a "strong" claim from one cosmetic ding. But equally, don't downgrade a clear hail strike or creased shingle to "weak" because the roof also shows aging. Hail and wind are co-equal claim drivers.

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

If the image is not a roof at all: set is_roof: false, not_roof_reason describing what the image shows, findings: [], damage_categories_present: [], overall_severity: "none", hail_confidence: "none", wind_confidence: "none", claim_strength: "no-claim", adjuster_notes: "".`;
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
