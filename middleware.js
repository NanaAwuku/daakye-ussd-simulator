// Basic Auth gate for the whole site. Password comes from the SITE_PASSWORD env var.
export const config = { matcher: '/:path*' };

export default function middleware(request) {
  const password = process.env.SITE_PASSWORD;
  const header = request.headers.get('authorization') || '';

  if (password && header.startsWith('Basic ')) {
    const decoded = atob(header.slice(6));
    const supplied = decoded.slice(decoded.indexOf(':') + 1);
    if (supplied === password) return;
  }

  return new Response('Password required', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="Daakye USSD Simulator", charset="UTF-8"' },
  });
}
