// Google sign-in: checks Google's ID token on the server, then the users collection.
import { GOOGLE_CLIENT_ID, findActiveUser } from './_auth.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  const credential = (req.body || {}).credential;
  if (!credential) return res.status(400).json({ error: 'Missing credential' });

  let info = null;
  try {
    const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential));
    if (r.ok) info = await r.json();
  } catch (_) {}
  if (!info || info.aud !== GOOGLE_CLIENT_ID || String(info.email_verified) !== 'true') {
    return res.status(401).json({ error: 'Google sign-in could not be verified. Please try again.' });
  }

  const email = String(info.email).toLowerCase().trim();
  try {
    const user = await findActiveUser(email);
    if (!user) return res.status(403).json({ error: `Access denied. ${email} is not authorised. Contact your administrator.` });
    return res.status(200).json({ user: { ...user, email, name: user.name || info.name || email, picture: info.picture || '' } });
  } catch (err) {
    console.error('google-verify:', err.message);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
}
