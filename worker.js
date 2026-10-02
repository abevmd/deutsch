/* ============================================================
   Deutsch Trainer — authentification (Cloudflare Worker + static assets)
   - comptes stockés dans D1 (binding : DB)
   - email de confirmation / réinitialisation via Resend (secret : RESEND_API_KEY)
   - toutes les pages et fichiers du site exigent une session valide
   Variables :
     DB               binding D1 (obligatoire)
     RESEND_API_KEY   secret Resend (obligatoire)
     MAIL_FROM        expéditeur, ex. "Deutsch Trainer <noreply@vonmittelmark.com>" (obligatoire)
     SIGNUP_ALLOWLIST facultatif : adresses ou domaines autorisés à s'inscrire,
                      séparés par des virgules (ex. "abel@vonmittelmark.com,@vonmittelmark.com").
                      Vide = inscription ouverte.
   ============================================================ */

const SESSION_COOKIE = 'dt_session';
const SESSION_DAYS = 30;
const VERIFY_HOURS = 24;
const RESET_HOURS = 1;
const PBKDF2_ITER = 100000; /* maximum accepté par le runtime Workers */
const MIN_PW = 8;

export default {
  fetch(request, env) {
    return onRequest({ request, env, next: () => env.ASSETS.fetch(request) });
  }
};

async function onRequest(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url);

  if (url.pathname.startsWith('/auth/')) {
    try {
      return await handleAuth(ctx, url);
    } catch (err) {
      console.error('auth error: ' + (err && err.message ? err.message : String(err)));
      return page('Erreur', '<p class="err">Une erreur est survenue. Réessayez dans un instant.</p>' +
        '<p><a href="/auth/login">Retour à la connexion</a></p>', 500);
    }
  }

  const user = await currentUser(request, env);
  if (!user) {
    if (request.method === 'GET' || request.method === 'HEAD') {
      const next = url.pathname + url.search;
      return redirect('/auth/login' + (next && next !== '/' ? '?next=' + encodeURIComponent(next) : ''));
    }
    return new Response('Unauthorized', { status: 401 });
  }

  const res = await ctx.next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'private, no-cache');
  out.headers.set('Vary', 'Cookie');
  return out;
}

/* ---------------- routes /auth/* ---------------- */
async function handleAuth(ctx, url) {
  const { request, env } = ctx;
  const path = url.pathname.replace(/\/+$/, '');
  const method = request.method;

  if (method === 'POST' && !sameOrigin(request, url)) return new Response('Forbidden', { status: 403 });

  switch (path) {
    case '/auth/login':
      if (method === 'POST') return doLogin(request, env, url);
      if (await currentUser(request, env)) return redirect(safeNext(url.searchParams.get('next')));
      return loginPage(url.searchParams.get('next'), msgFromQuery(url));
    case '/auth/signup':
      if (method === 'POST') return doSignup(request, env, url);
      return signupPage();
    case '/auth/verify':
      return doVerify(env, url);
    case '/auth/resend':
      if (method === 'POST') return doResend(request, env, url);
      return resendPage();
    case '/auth/forgot':
      if (method === 'POST') return doForgot(request, env, url);
      return forgotPage();
    case '/auth/reset':
      if (method === 'POST') return doReset(request, env, url);
      return resetPage(url.searchParams.get('token') || '');
    case '/auth/logout':
      return doLogout(request, env);
    default:
      return page('Introuvable', '<p>Page introuvable.</p><p><a href="/auth/login">Connexion</a></p>', 404);
  }
}

/* ---------------- actions ---------------- */
async function doLogin(request, env, url) {
  const f = await request.formData();
  const email = normEmail(f.get('email'));
  const pw = String(f.get('password') || '');
  const next = String(f.get('next') || '');
  const user = email ? await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first() : null;
  const ok = user ? await verifyPassword(pw, user.pw_salt, user.pw_hash) : (await hashPassword(pw, randomHex(16)), false);
  if (!ok) return loginPage(next, { err: 'Adresse email ou mot de passe incorrect.' }, email, 401);
  if (!user.verified) {
    return loginPage(next, { err: 'Votre adresse email n’est pas encore confirmée. Cliquez sur le lien reçu par email, ' +
      'ou <a href="/auth/resend">renvoyez l’email de confirmation</a>.' }, email, 403);
  }
  const token = randomHex(32);
  const exp = Date.now() + SESSION_DAYS * 864e5;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Date.now()),
    env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').bind(await sha256(token), user.id, exp)
  ]);
  return redirect(safeNext(next), { 'Set-Cookie': cookie(SESSION_COOKIE, token, SESSION_DAYS * 86400) });
}

async function doSignup(request, env, url) {
  const f = await request.formData();
  const email = normEmail(f.get('email'));
  const pw = String(f.get('password') || '');
  const pw2 = String(f.get('password2') || '');
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return signupPage({ err: 'Adresse email invalide.' }, email, 400);
  if (pw.length < MIN_PW) return signupPage({ err: 'Le mot de passe doit contenir au moins ' + MIN_PW + ' caractères.' }, email, 400);
  if (pw !== pw2) return signupPage({ err: 'Les deux mots de passe ne correspondent pas.' }, email, 400);
  if (!allowedToSignup(email, env)) return signupPage({ err: 'Les inscriptions sont réservées. Contactez l’administrateur du site.' }, email, 403);

  const existing = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (existing && existing.verified) {
    /* même message qu'une inscription normale : on ne révèle pas quelles adresses existent */
    return page('Vérifiez vos emails', checkMailHtml(email));
  }
  const salt = randomHex(16);
  const hash = await hashPassword(pw, salt);
  let userId;
  if (existing) {
    await env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ? WHERE id = ?').bind(hash, salt, existing.id).run();
    userId = existing.id;
  } else {
    const r = await env.DB.prepare('INSERT INTO users (email, pw_hash, pw_salt, verified, created_at) VALUES (?, ?, ?, 0, ?) RETURNING id')
      .bind(email, hash, salt, Date.now()).first();
    userId = r.id;
  }
  await sendVerifyMail(env, url, userId, email);
  return page('Vérifiez vos emails', checkMailHtml(email));
}

async function doVerify(env, url) {
  const token = url.searchParams.get('token') || '';
  const row = token ? await env.DB.prepare("SELECT * FROM tokens WHERE token_hash = ? AND kind = 'verify'")
    .bind(await sha256(token)).first() : null;
  if (!row || row.expires_at < Date.now()) {
    return page('Lien invalide', '<p class="err">Ce lien de confirmation est invalide ou a expiré.</p>' +
      '<p><a href="/auth/resend">Recevoir un nouveau lien</a></p>', 400);
  }
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET verified = 1 WHERE id = ?').bind(row.user_id),
    env.DB.prepare("DELETE FROM tokens WHERE user_id = ? AND kind = 'verify'").bind(row.user_id)
  ]);
  return redirect('/auth/login?m=verified');
}

async function doResend(request, env, url) {
  const f = await request.formData();
  const email = normEmail(f.get('email'));
  const user = email ? await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first() : null;
  if (user && !user.verified) await sendVerifyMail(env, url, user.id, email);
  return page('Vérifiez vos emails', checkMailHtml(email));
}

async function doForgot(request, env, url) {
  const f = await request.formData();
  const email = normEmail(f.get('email'));
  const user = email ? await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first() : null;
  if (user && user.verified) {
    const token = await newToken(env, user.id, 'reset', RESET_HOURS);
    const link = url.origin + '/auth/reset?token=' + token;
    await sendMail(env, email, 'Réinitialiser votre mot de passe — Deutsch Trainer',
      mailHtml('Réinitialiser votre mot de passe',
        'Vous avez demandé à réinitialiser le mot de passe de votre compte Deutsch Trainer.',
        link, 'Choisir un nouveau mot de passe',
        'Ce lien est valable ' + RESET_HOURS + ' heure. Si vous n’êtes pas à l’origine de cette demande, ignorez cet email.'));
  }
  return page('Vérifiez vos emails', '<p>Si un compte confirmé existe pour <b>' + esc(email) + '</b>, ' +
    'un email contenant un lien de réinitialisation vient d’être envoyé.</p><p><a href="/auth/login">Retour à la connexion</a></p>');
}

async function doReset(request, env, url) {
  const f = await request.formData();
  const token = String(f.get('token') || '');
  const pw = String(f.get('password') || '');
  const pw2 = String(f.get('password2') || '');
  if (pw.length < MIN_PW) return resetPage(token, { err: 'Le mot de passe doit contenir au moins ' + MIN_PW + ' caractères.' }, 400);
  if (pw !== pw2) return resetPage(token, { err: 'Les deux mots de passe ne correspondent pas.' }, 400);
  const row = token ? await env.DB.prepare("SELECT * FROM tokens WHERE token_hash = ? AND kind = 'reset'")
    .bind(await sha256(token)).first() : null;
  if (!row || row.expires_at < Date.now()) {
    return page('Lien invalide', '<p class="err">Ce lien est invalide ou a expiré.</p><p><a href="/auth/forgot">Recommencer</a></p>', 400);
  }
  const salt = randomHex(16);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET pw_hash = ?, pw_salt = ? WHERE id = ?').bind(await hashPassword(pw, salt), salt, row.user_id),
    env.DB.prepare("DELETE FROM tokens WHERE user_id = ? AND kind = 'reset'").bind(row.user_id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(row.user_id)
  ]);
  return redirect('/auth/login?m=reset');
}

async function doLogout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
  return redirect('/auth/login?m=out', { 'Set-Cookie': cookie(SESSION_COOKIE, '', 0) });
}

/* ---------------- session ---------------- */
async function currentUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  const row = await env.DB.prepare(
    'SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND u.verified = 1'
  ).bind(await sha256(token), Date.now()).first();
  return row || null;
}

/* ---------------- emails ---------------- */
async function sendVerifyMail(env, url, userId, email) {
  const token = await newToken(env, userId, 'verify', VERIFY_HOURS);
  const link = url.origin + '/auth/verify?token=' + token;
  await sendMail(env, email, 'Confirmez votre adresse email — Deutsch Trainer',
    mailHtml('Bienvenue sur Deutsch Trainer',
      'Pour activer votre compte, confirmez votre adresse email en cliquant sur le bouton ci-dessous.',
      link, 'Confirmer mon adresse email',
      'Ce lien est valable ' + VERIFY_HOURS + ' heures. Si vous n’avez pas créé de compte, ignorez cet email.'));
}

async function newToken(env, userId, kind, hours) {
  const token = randomHex(32);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM tokens WHERE user_id = ? AND kind = ?').bind(userId, kind),
    env.DB.prepare('INSERT INTO tokens (token_hash, user_id, kind, expires_at) VALUES (?, ?, ?, ?)')
      .bind(await sha256(token), userId, kind, Date.now() + hours * 3600e3)
  ]);
  return token;
}

async function sendMail(env, to, subject, html) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, html })
  });
  if (!r.ok) throw new Error('Resend ' + r.status + ' ' + (await r.text()));
}

function mailHtml(title, intro, link, cta, outro) {
  return '<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#241f1c">' +
    '<h2 style="font-family:Georgia,serif;margin:0 0 16px">' + title + '</h2>' +
    '<p style="line-height:1.5">' + intro + '</p>' +
    '<p style="margin:24px 0"><a href="' + link + '" style="background:#1c1917;color:#e7c46a;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:600">' + cta + '</a></p>' +
    '<p style="font-size:13px;color:#6f665c;line-height:1.5">Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :<br>' +
    '<a href="' + link + '" style="color:#9a7508;word-break:break-all">' + link + '</a></p>' +
    '<p style="font-size:13px;color:#6f665c">' + outro + '</p></div>';
}

/* ---------------- pages ---------------- */
function msgFromQuery(url) {
  const m = url.searchParams.get('m');
  if (m === 'verified') return { ok: 'Adresse email confirmée. Vous pouvez vous connecter.' };
  if (m === 'reset') return { ok: 'Mot de passe modifié. Connectez-vous avec le nouveau mot de passe.' };
  if (m === 'out') return { ok: 'Vous êtes déconnecté.' };
  return null;
}
function msgHtml(msg) {
  if (!msg) return '';
  return msg.err ? '<p class="err">' + msg.err + '</p>' : '<p class="ok">' + msg.ok + '</p>';
}
function checkMailHtml(email) {
  return '<p>Si l’adresse <b>' + esc(email) + '</b> peut être inscrite, un email de confirmation vient d’y être envoyé. ' +
    'Cliquez sur le lien qu’il contient pour activer votre compte (pensez à vérifier les spams).</p>' +
    '<p><a href="/auth/login">Retour à la connexion</a> · <a href="/auth/resend">Renvoyer l’email</a></p>';
}
function loginPage(next, msg, email = '', status = 200) {
  return page('Connexion', msgHtml(msg) +
    '<form method="post" action="/auth/login">' +
    '<input type="hidden" name="next" value="' + esc(next || '') + '">' +
    '<label>Adresse email<input type="email" name="email" required autocomplete="email" value="' + esc(email) + '"></label>' +
    '<label>Mot de passe<input type="password" name="password" required autocomplete="current-password"></label>' +
    '<button type="submit">Se connecter</button></form>' +
    '<p class="links"><a href="/auth/signup">Créer un compte</a> · <a href="/auth/forgot">Mot de passe oublié</a></p>', status);
}
function signupPage(msg, email = '', status = 200) {
  return page('Créer un compte', msgHtml(msg) +
    '<form method="post" action="/auth/signup">' +
    '<label>Adresse email<input type="email" name="email" required autocomplete="email" value="' + esc(email) + '"></label>' +
    '<label>Mot de passe <small>(' + MIN_PW + ' caractères minimum)</small><input type="password" name="password" required minlength="' + MIN_PW + '" autocomplete="new-password"></label>' +
    '<label>Confirmer le mot de passe<input type="password" name="password2" required minlength="' + MIN_PW + '" autocomplete="new-password"></label>' +
    '<button type="submit">Créer mon compte</button></form>' +
    '<p class="links">Déjà inscrit ? <a href="/auth/login">Se connecter</a></p>', status);
}
function resendPage() {
  return page('Renvoyer la confirmation',
    '<form method="post" action="/auth/resend">' +
    '<label>Adresse email<input type="email" name="email" required autocomplete="email"></label>' +
    '<button type="submit">Renvoyer l’email de confirmation</button></form>' +
    '<p class="links"><a href="/auth/login">Retour à la connexion</a></p>');
}
function forgotPage() {
  return page('Mot de passe oublié',
    '<form method="post" action="/auth/forgot">' +
    '<label>Adresse email<input type="email" name="email" required autocomplete="email"></label>' +
    '<button type="submit">Recevoir un lien de réinitialisation</button></form>' +
    '<p class="links"><a href="/auth/login">Retour à la connexion</a></p>');
}
function resetPage(token, msg, status = 200) {
  return page('Nouveau mot de passe', msgHtml(msg) +
    '<form method="post" action="/auth/reset">' +
    '<input type="hidden" name="token" value="' + esc(token) + '">' +
    '<label>Nouveau mot de passe <small>(' + MIN_PW + ' caractères minimum)</small><input type="password" name="password" required minlength="' + MIN_PW + '" autocomplete="new-password"></label>' +
    '<label>Confirmer le mot de passe<input type="password" name="password2" required minlength="' + MIN_PW + '" autocomplete="new-password"></label>' +
    '<button type="submit">Enregistrer</button></form>', status);
}

function page(title, body, status = 200) {
  const html = `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#1c1917"><meta name="robots" content="noindex">
<title>${title} — Deutsch Trainer</title>
<style>
:root{--bg:#12100e;--card:#241f1c;--line:#3a332e;--txt:#f2ede7;--dim:#a89e94;--gold:#e7c46a;--green:#5fb87a;--green-bg:#16281c;--red:#e0736b;--red-bg:#2c1a19;--in:#1c1917}
@media (prefers-color-scheme: light){:root{--bg:#faf7f2;--card:#fff;--line:#e2d9cb;--txt:#241f1c;--dim:#6f665c;--gold:#9a7508;--green:#2f7d4c;--green-bg:#e6f4ea;--red:#b83a30;--red-bg:#fceceb;--in:#fffdf9}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--txt);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;align-items:flex-start;justify-content:center;padding:48px 16px}
main{width:100%;max-width:400px}
.brand{font-family:Georgia,"Times New Roman",serif;font-size:24px;font-weight:700;margin:0 0 20px;text-align:center}
.brand span{color:var(--gold)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px}
h1{font-size:19px;margin:0 0 16px;font-weight:650}
label{display:block;font-size:13px;font-weight:600;color:var(--dim);margin:0 0 14px}
label small{font-weight:400}
input{display:block;width:100%;margin-top:6px;padding:12px 13px;border-radius:11px;border:1.5px solid var(--line);background:var(--in);color:var(--txt);font:inherit}
input:focus{outline:none;border-color:var(--gold)}
button{width:100%;padding:13px;border:none;border-radius:11px;background:var(--gold);color:#1c1917;font:inherit;font-weight:650;cursor:pointer;margin-top:4px}
a{color:var(--gold)}
.links{text-align:center;font-size:14px;margin:18px 0 0}
.err{background:var(--red-bg);color:var(--red);padding:10px 12px;border-radius:10px;font-size:14px}
.ok{background:var(--green-bg);color:var(--green);padding:10px 12px;border-radius:10px;font-size:14px}
</style></head><body><main>
<div class="brand">Deutsch<span>·</span>Trainer</div>
<div class="card"><h1>${title}</h1>${body}</div>
</main></body></html>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

/* ---------------- utilitaires ---------------- */
function redirect(location, extra = {}) {
  return new Response(null, { status: 303, headers: { Location: location, 'Cache-Control': 'no-store', ...extra } });
}
function safeNext(n) {
  n = String(n || '');
  return n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/auth/') ? n : '/';
}
function sameOrigin(request, url) {
  const o = request.headers.get('Origin');
  return !o || o === url.origin;
}
function normEmail(e) { return String(e || '').trim().toLowerCase(); }
function allowedToSignup(email, env) {
  const list = String(env.SIGNUP_ALLOWLIST || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!list.length) return true;
  return list.some(x => x.startsWith('@') ? email.endsWith(x) : email === x);
}
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function getCookie(request, name) {
  const h = request.headers.get('Cookie') || '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function cookie(name, value, maxAge) {
  return name + '=' + encodeURIComponent(value) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + maxAge;
}
function randomHex(bytes) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('');
}
function toHex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function fromHex(h) { return new Uint8Array(h.match(/../g).map(x => parseInt(x, 16))); }
async function sha256(s) { return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))); }
async function hashPassword(pw, saltHex) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: PBKDF2_ITER }, key, 256);
  return toHex(bits);
}
async function verifyPassword(pw, saltHex, hashHex) {
  const a = fromHex(await hashPassword(pw, saltHex));
  const b = fromHex(hashHex);
  if (a.length !== b.length) return false;
  if (crypto.subtle.timingSafeEqual) return crypto.subtle.timingSafeEqual(a, b);
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
