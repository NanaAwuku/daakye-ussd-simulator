// Password gate for the whole site. Password comes from the SITE_PASSWORD env var.
// Unauthenticated visitors get a login page; a correct password sets a session cookie.
export const config = { matcher: '/:path*' };

const COOKIE = 'daakye_auth';
const FLASH = 'daakye_login_failed'; // one-shot marker so the error shows once, not on every reload
const MAX_AGE = 60 * 60 * 24 * 7; // 7 days

async function token(password) {
  const data = new TextEncoder().encode('daakye-ussd:' + password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function readCookie(request, name) {
  const header = request.headers.get('cookie') || '';
  const match = header.split(/;\s*/).find(c => c.startsWith(name + '='));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

export default async function middleware(request) {
  const password = process.env.SITE_PASSWORD;
  if (!password) return new Response('Site password is not configured.', { status: 500 });

  const url = new URL(request.url);
  const expected = await token(password);

  if (url.pathname === '/logout') {
    return new Response(null, {
      status: 303,
      headers: { Location: '/', 'Set-Cookie': `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` },
    });
  }

  if (request.method === 'POST' && url.pathname === '/login') {
    const form = await request.formData();
    const supplied = String(form.get('password') || '');
    if (safeEqual(await token(supplied), expected)) {
      return new Response(null, {
        status: 303,
        headers: { Location: '/', 'Set-Cookie': `${COOKIE}=${expected}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax` },
      });
    }
    // Redirect instead of rendering, so reload/back never replays the failed POST.
    return new Response(null, {
      status: 303,
      headers: { Location: '/', 'Set-Cookie': `${FLASH}=1; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax` },
    });
  }

  if (url.pathname === '/login') return new Response(null, { status: 303, headers: { Location: '/' } });

  if (safeEqual(readCookie(request, COOKIE), expected)) return; // authenticated: serve the site

  const page = loginPage(readCookie(request, FLASH) === '1');
  page.headers.append('Set-Cookie', `${FLASH}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  return page;
}

function loginPage(failed) {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Daakye USSD Simulator</title>
<style>
  :root {
    --bg: #edf3ef; --card: #ffffff; --fg: #172b29; --muted: #5b6f68;
    --border: #cad9d0; --accent: #175a40; --accent-fg: #ffffff; --error: #a12d21;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #152523; --card: #22342f; --fg: #e6efed; --muted: #9fb5ab;
      --border: #425b4d; --accent: #b4dfbd; --accent-fg: #173625; --error: #ffb7aa;
    }
  }
  :root[data-theme="dark"] {
    --bg: #152523; --card: #22342f; --fg: #e6efed; --muted: #9fb5ab;
    --border: #425b4d; --accent: #b4dfbd; --accent-fg: #173625; --error: #ffb7aa;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
    background: var(--bg); color: var(--fg);
    font: 15px/1.5 -apple-system, system-ui, "Segoe UI", sans-serif;
  }
  .card {
    width: 100%; max-width: 360px; background: var(--card);
    border: 1px solid var(--border); border-radius: 14px; padding: 28px 24px;
  }
  .brand { font-weight: 700; letter-spacing: .08em; font-size: 13px; color: var(--accent); }
  h1 { font-size: 20px; margin: 6px 0 4px; }
  p { margin: 0 0 20px; color: var(--muted); font-size: 14px; }
  label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; }
  input {
    width: 100%; padding: 11px 12px; font: inherit; color: var(--fg); background: var(--bg);
    border: 1px solid var(--border); border-radius: 8px;
  }
  input:focus { outline: 2px solid var(--accent); outline-offset: 1px; border-color: transparent; }
  .error { color: var(--error); font-size: 13px; margin-top: 8px; }
  button {
    width: 100%; margin-top: 16px; padding: 11px; font: inherit; font-weight: 600;
    color: var(--accent-fg); background: var(--accent); border: 0; border-radius: 8px; cursor: pointer;
  }
  button:hover { filter: brightness(1.08); }
</style>
</head>
<body>
<form class="card" method="post" action="/login">
  <div class="brand">DAAKYE</div>
  <h1>USSD Simulator</h1>
  <p>Enter the password to view this demo.</p>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required autofocus${failed ? ' aria-describedby="err"' : ''}>
  ${failed ? '<div id="err" class="error" role="alert">Incorrect password. Try again.</div>' : ''}
  <button type="submit">Continue</button>
</form>
</body>
</html>`;
  return new Response(html, {
    status: failed ? 401 : 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
