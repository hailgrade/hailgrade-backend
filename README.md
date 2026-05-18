# HailGrade Backend

The API server that powers hailgrade.com. Handles:

- User signup / login (email + password, JWT sessions)
- Stripe subscription billing
- Proxying photo analyses to Claude using YOUR Anthropic API key (users pay you, not Anthropic)
- Logging every analysis and every finding to a Postgres database — your proprietary roof damage dataset

## What this replaces

Right now, hailgrade.com asks users to paste their own Anthropic API key. Each photo they take calls Anthropic directly from their phone, billed to their Anthropic account.

Once this backend is live, hailgrade.com will instead:
1. Ask users to **sign up with email + password**
2. Charge them **monthly via Stripe**
3. Send photos to **YOUR server**, which then calls Anthropic with **YOUR key**
4. Store the analysis in **your database**

## What you need to deploy this

1. **A Render account** — https://dashboard.render.com (already done)
2. **An Anthropic API key with billing set up** — https://console.anthropic.com/settings/keys
3. **A Stripe account** — https://dashboard.stripe.com/register
4. **A domain or subdomain for the API** — recommended: `api.hailgrade.com`

## Step-by-step deployment

### 1. Create the Render service

In Render dashboard:
- Click **"New +"** → **"Blueprint"**
- Upload the contents of this folder as a Git repo (or use Render's "Deploy from file" if available)
- Render will read `render.yaml`, create both the web service AND the Postgres database in one shot

Alternative without Git: New → Web Service → "Deploy from a public Git repository" pointing at a GitHub repo you create with these files. We can walk through this together.

### 2. Set the environment variables

In the Render dashboard, open `hailgrade-api` → Environment → and fill in the values marked `sync: false` in `render.yaml`:

- `ANTHROPIC_API_KEY` — your Anthropic key (starts with `sk-ant-`)
- `STRIPE_SECRET_KEY` — from Stripe → Developers → API keys → "Secret key" (starts with `sk_test_...` while testing, `sk_live_...` when ready)
- `STRIPE_WEBHOOK_SECRET` — created in step 4 below
- `STRIPE_PRICE_SOLO` — created in step 3 below
- `STRIPE_PRICE_FIRM` — created in step 3 below

Other values (`JWT_SECRET`, `DATABASE_URL`, `NODE_ENV`) are set automatically by the blueprint.

### 3. Create Stripe products

In Stripe dashboard:

- **Products** → **+ Add product** → "HailGrade Solo" — recurring monthly, $49/mo (or whatever you choose)
- Copy the **Price ID** (looks like `price_1Abc...`) → paste into Render env var `STRIPE_PRICE_SOLO`
- Repeat for "HailGrade Firm" — $149/mo or your firm tier price → `STRIPE_PRICE_FIRM`

### 4. Set up the Stripe webhook

The webhook tells the server when a user subscribes, cancels, or fails to pay.

In Stripe:
- **Developers** → **Webhooks** → **+ Add endpoint**
- Endpoint URL: `https://hailgrade-api.onrender.com/webhooks/stripe` (or your actual Render URL — Render shows it after first deploy)
- Events to listen for:
  - `checkout.session.completed`
  - `customer.subscription.created`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
  - `invoice.payment_failed`
- After creating, click **"Reveal signing secret"** → copy the value (starts with `whsec_`) → paste into Render env var `STRIPE_WEBHOOK_SECRET`

### 5. Custom domain (recommended)

In Render → `hailgrade-api` → Settings → Custom Domain → add `api.hailgrade.com`.
Then in your domain DNS, add the CNAME record Render shows you.

### 6. Promote yourself to admin

Once you sign up for an account via the live API, your user row will have `role = 'user'`. To bypass the subscription check while testing, run this once in the Render database shell:

```sql
UPDATE users SET role = 'admin' WHERE email = 'claims@smithadjusters.com';
```

Admins always pass the subscription check (handy for testing or comping certain users).

## API reference

### Auth

```
POST /auth/signup
  Body: { email, password, full_name?, license_number?, firm_name? }
  → { token, user }

POST /auth/login
  Body: { email, password }
  → { token, user }

GET /me              (Bearer token)
  → { user }

PATCH /me            (Bearer token)
  Body: { full_name?, license_number?, firm_name? }
  → { ok: true }
```

### Analysis

```
POST /analyze       (Bearer token + active subscription)
  Body: {
    image: "<base64 jpeg/png>",
    media_type: "image/jpeg" | "image/png",
    slope: "N" | "S" | ...,
    context: { dateOfLoss?, carrier?, gps?: {lat, lng}, testSquare?: {hits, w, h} },
    photo_local_id?: "P...",   // your client-side id
    claim_local_id?: "C..."    // your client-side id
  }
  → {
    ok: true,
    analysis_id: 123,
    result: { is_roof, findings, ... },   // same shape as before
    cost_cents: 2
  }
```

### Billing

```
POST /billing/checkout     (Bearer token)
  Body: { plan: "solo" | "firm" }
  → { url: "https://checkout.stripe.com/..." }    // redirect the user here

POST /billing/portal       (Bearer token, after they've subscribed)
  → { url: "https://billing.stripe.com/..." }     // redirect to manage subscription
```

## Frontend changes

Once this is deployed at `api.hailgrade.com`, the next step is updating `index.html` to:
- Replace the API-key setup screen with email/password signup/login
- Call `/analyze` instead of `api.anthropic.com/v1/messages`
- Add a "Subscribe" call-to-action that hits `/billing/checkout`
- Add a "Manage subscription" link that hits `/billing/portal`

We'll do that as the next step after the backend is up and reachable.

## Costs (approximate)

- Render web service: **$7/mo** (starter) or **free** while testing (sleeps after 15 min idle)
- Render Postgres: **free** (1GB) → **$7/mo** (10GB) before production
- Stripe: **2.9% + 30¢** per transaction; no monthly fee
- Anthropic: ~**$0.01–0.03 per photo analysis** at current Claude Sonnet 4.6 pricing
- Total fixed monthly: **$14/mo** at production tier; **$0** while testing

## Local development

```bash
cd backend
cp .env.example .env       # then fill in real values
npm install
npm run dev                # auto-reloads on file changes
```

Server runs on http://localhost:3000. Use a tunnel like `ngrok http 3000` if you want to test Stripe webhooks against your local server.
