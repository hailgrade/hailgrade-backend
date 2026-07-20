-- HailGrade database schema
-- Run this once after creating the Render Postgres database.
-- The migrate.js script applies this automatically on first server boot.

CREATE TABLE IF NOT EXISTS users (
  id              SERIAL PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  password_hash   TEXT NOT NULL,
  full_name       TEXT,
  license_number  TEXT,
  firm_name       TEXT,
  role            TEXT NOT NULL DEFAULT 'user',  -- 'user' or 'admin'
  stripe_customer_id TEXT,
  plan            TEXT,            -- 'solo', 'firm', null
  plan_status     TEXT,            -- 'active', 'trialing', 'past_due', 'canceled', null
  plan_renews_at  TIMESTAMPTZ,
  monthly_analyses_used  INTEGER NOT NULL DEFAULT 0,
  monthly_analyses_reset_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (lower(email));

-- Every Claude analysis call is logged here for billing, debugging, and dataset building.
-- The raw_response is the full JSON the model returned — keep it for retraining/auditing.
CREATE TABLE IF NOT EXISTS analyses (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  claim_local_id  TEXT,            -- the C... ID from the client; we don't own claims server-side yet
  photo_local_id  TEXT,
  slope           TEXT,
  gps_lat         DOUBLE PRECISION,
  gps_lng         DOUBLE PRECISION,
  date_of_loss    DATE,
  carrier         TEXT,
  is_roof         BOOLEAN,
  overall_severity TEXT,
  roof_material   TEXT,
  damage_categories TEXT[],         -- array of category strings present in the analysis
  findings_count  INTEGER DEFAULT 0,
  prompt_tokens   INTEGER,
  output_tokens   INTEGER,
  cost_cents      INTEGER,          -- our cost from Anthropic, in cents
  raw_response    JSONB,            -- full Claude response for future use
  model           TEXT,
  status          TEXT DEFAULT 'ok',  -- 'ok', 'error', 'not_roof'
  error_message   TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS analyses_user_idx ON analyses (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS analyses_categories_idx ON analyses USING gin (damage_categories);

-- Each finding extracted from the analysis. Indexed so we can query "all hail findings in PA last June" etc.
CREATE TABLE IF NOT EXISTS findings (
  id              SERIAL PRIMARY KEY,
  analysis_id     INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  finding_local_id TEXT,
  category        TEXT,             -- hail, wind, granular_loss, wear_tear, defect, other
  cause_origin    TEXT,             -- storm-related, non-storm, ambiguous
  severity        TEXT,             -- severe, moderate, minor
  type            TEXT,
  description     TEXT,
  bbox_x          REAL,
  bbox_y          REAL,
  bbox_w          REAL,
  bbox_h          REAL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS findings_analysis_idx ON findings (analysis_id);
CREATE INDEX IF NOT EXISTS findings_category_idx ON findings (category, created_at DESC);

-- Stripe events we've already processed (for webhook idempotency)
CREATE TABLE IF NOT EXISTS stripe_events (
  id            TEXT PRIMARY KEY,
  type          TEXT NOT NULL,
  processed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Password rotation: set when a user changes their password. Any token issued
-- BEFORE this timestamp is rejected, so changing the password signs out other devices.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;

-- Track sign-ins so the admin dashboard can show who is actually using the app.
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
