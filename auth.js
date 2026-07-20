// JWT-based session helpers + middleware.
// Tokens are signed with JWT_SECRET (an env var, any long random string).
// We use 30-day tokens stored in localStorage on the client — same UX as the API key was.
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { one } from './db.js';

const TOKEN_TTL = '30d';

if (!process.env.JWT_SECRET) {
  console.warn('[auth] JWT_SECRET not set — tokens will fail. Set it in Render env vars.');
}

export function hashPassword(plain) {
  return bcrypt.hash(plain, 12);
}

export function checkPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

export function signToken(user) {
  return jwt.sign(
    { uid: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: TOKEN_TTL }
  );
}

// Express middleware. Pulls Bearer token from Authorization header, loads user, attaches to req.
export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'missing_token' });
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await one('SELECT * FROM users WHERE id = $1', [payload.uid]);
    if (!user) return res.status(401).json({ error: 'user_not_found' });
    if (user.active === false) return res.status(403).json({ error: 'account_deactivated', message: 'This account has been deactivated by your organization administrator.' });
    // A password change signs out every OTHER device: any token minted before the change
    // is refused. Compared at second precision because JWT `iat` is whole seconds.
    if (user.password_changed_at) {
      const changedSec = Math.floor(new Date(user.password_changed_at).getTime() / 1000);
      const iatSec = payload.iat || 0;
      if (iatSec && changedSec && iatSec < changedSec) {
        return res.status(401).json({ error: 'password_changed', message: 'Your password was changed. Please sign in again.' });
      }
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token', detail: err.message });
  }
}

// Stricter wrapper — requires an active subscription. Used on the analyze endpoint.
export async function requireActiveSubscription(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'no_user' });
  // Admin users always pass (so you can test as Alexander)
  if (req.user.role === 'admin') return next();
  const ok = ['active', 'trialing'].includes(req.user.plan_status);
  if (!ok) {
    return res.status(402).json({
      error: 'no_active_subscription',
      message: 'No active HailGrade subscription. Subscribe or update your billing.',
      plan_status: req.user.plan_status || 'none'
    });
  }
  next();
}
