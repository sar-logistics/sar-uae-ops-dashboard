// Shared sign-in helpers for api/sso-verify.js and api/google-verify.js (SAR
// dashboard sign-in SOP, Template A). Not an endpoint: Vercel skips files starting with _.
import crypto from 'crypto';
import { MongoClient } from 'mongodb';

export const GOOGLE_CLIENT_ID = 'UAE_GOOGLE_CLIENT_ID.apps.googleusercontent.com'  // TODO: UAE Google sign-in client;
const HUB_ISSUER = 'sar-systems-hub';
const DEFAULT_HUB_ORIGIN = 'https://systems.sarlogisolutions.com';
export const DB_NAME = process.env.MONGO_DB || 'sar-uae-ops';

let clientPromise;
export function getDb() {
  if (!clientPromise) {
    clientPromise = new MongoClient(process.env.MONGO_URI, { maxPoolSize: 5, serverSelectionTimeoutMS: 10000 })
      .connect()
      .catch((err) => { clientPromise = null; throw err; });
  }
  return clientPromise.then((c) => c.db(DB_NAME));
}

// The one access check both sign-ins use.
export async function findActiveUser(email) {
  return (await getDb()).collection('users').findOne({ email, active: true });
}

function b64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// Verifies the Hub's 60-second launch token (HS256, signed with SSO_SHARED_SECRET). Throws if invalid.
export function verifyHubToken(token) {
  const secret = process.env.SSO_SHARED_SECRET;
  if (!secret) throw Object.assign(new Error('SSO_SHARED_SECRET is not set'), { misconfigured: true });
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [h, p, s] = parts;
  if (JSON.parse(b64url(h).toString('utf8')).alg !== 'HS256') throw new Error('unexpected alg');
  const expected = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest();
  const actual = b64url(s);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) throw new Error('bad signature');
  const payload = JSON.parse(b64url(p).toString('utf8'));
  if (typeof payload.exp !== 'number' || Date.now() / 1000 >= payload.exp) throw new Error('token expired');
  if (payload.iss !== HUB_ISSUER) throw new Error('unexpected issuer');
  return payload;
}

// Only the Hub itself (production or its Vercel previews) may be used to load the widget script.
export function sanitizeHubOrigin(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol === 'https:' && (u.hostname === 'systems.sarlogisolutions.com' ||
        /^dashboards(-[a-z0-9]+)?-git-[a-z0-9-]+-sar-strategy\.vercel\.app$/.test(u.hostname))) return u.origin;
  } catch (_) {}
  return DEFAULT_HUB_ORIGIN;
}
