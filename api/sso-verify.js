// Hub sign-in: the SAR Systems Hub POSTs a launch token here (through its /dashboards/<slug> proxy).
import { verifyHubToken, findActiveUser, sanitizeHubOrigin } from './_auth.js';

const toScript = (v) => JSON.stringify(v ?? '').replace(/</g, '\\u003c');

function handoffPage(user, widgetToken, slug, hubOrigin) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Signing in…</title></head><body>
<p>Signing you in…</p>
<script>
  try {
    sessionStorage.setItem('sar_hub_sso_user', JSON.stringify(${toScript(user)}));
    var widgetToken = ${toScript(widgetToken)};
    if (widgetToken) {
      sessionStorage.setItem('sar_hub_widget_token', widgetToken);
      sessionStorage.setItem('sar_hub_current_slug', ${toScript(slug)});
      sessionStorage.setItem('sar_hub_origin', ${toScript(hubOrigin)});
    }
  } catch (e) {}
  location.replace('/');
</script></body></html>`;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Method not allowed');
  const body = req.body || {};
  if (!body.sso_token) return res.status(400).send('Missing sso_token');

  let payload;
  try {
    payload = verifyHubToken(body.sso_token);
  } catch (err) {
    console.error('sso-verify:', err.message);
    if (err.misconfigured) return res.status(500).send('Server misconfiguration. Contact your administrator.');
    return res.status(401).send('Invalid or expired sign-in link. Please return to the Hub and try again.');
  }

  const email = String(payload.email || '').toLowerCase().trim();
  if (!email) return res.status(400).send('Token missing email');
  const slug = /^[a-z0-9][a-z0-9_-]{0,79}$/i.test(payload.slug || '') ? payload.slug : '';

  try {
    const user = await findActiveUser(email);
    if (!user) return res.status(403).send('Access denied. Your account is not registered in this dashboard. Contact your administrator.');
    const profile = { ...user, email, name: user.name || email };
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(handoffPage(profile, body.widget_token, slug, sanitizeHubOrigin(body.hub_origin)));
  } catch (err) {
    console.error('sso-verify: lookup error:', err.message);
    return res.status(500).send('Something went wrong. Please try again.');
  }
}
