# Safari Session PoC

Demo sign-in for checking whether locked Safari sends a session-authenticated request before app-lock or Private Browsing authentication. Both versions accept arbitrary test credentials and use synthetic data only. This is a session demonstration, not real account authentication.

## Netlify HTTPS login

### Authenticated callback PoC

Any non-empty test username and password can sign in. Usernames are trimmed and limited
to 80 characters; passwords are limited to 256 characters. Use made-up credentials.
The username is stored in the server-side JSON session, not taken from callback query
parameters. Passwords are discarded, never stored or sent in callbacks.

Supply your own callback URL at request time using `/?url=...`; no fixed URL is required.
Optionally restrict destinations with `CALLBACK_ALLOWED_HOSTS`, a comma-separated list
of exact hostnames (Netlify environment-variable scope: Functions). No wildcard matching is used.
Without this optional setting, any public HTTPS receiver can be supplied at request time.
The receiver must support HTTPS on port 443, resolve to public IPv4 addresses and accept POST.
Requests never follow redirects, and private/reserved addresses are rejected.
Do not configure other people's endpoints.

After signing in, open this URL from another app while Safari remains locked:

```text
https://safari-poc.netlify.app/?url=https%3A%2F%2Fyour-unique-oast-host.example%2F%3Ftest%3Dlocked-001
```

URL-encode the entire callback URL, including its query parameters. The server validates
the session before making one HTTPS POST to the receiver. For username `alice`, the body is:

```text
This Poc by xlsize0bruh
Username: alice
```

Only the fixed PoC text and signed-in test username are forwarded, not cookies,
passwords or private markers. Logged-out, forged
and revoked sessions cannot send callbacks. Signing in does not automatically
replay a blocked callback. Use a new test ID for each attempt and compare callback timing
with a screen recording showing that Safari authentication did not succeed.

This GET-triggered action is intentional for the PoC, not production web design.
A callback demonstrates server-side execution, not that Safari's UI was unlocked.
The hosted guest rejection, login, callback validation and logout flows have been
verified. Actual delivery to your chosen endpoint should be checked with your own
test receiver; no third-party callback was sent during implementation verification.

Open https://safari-poc.netlify.app/?test=private-lock-001 and sign in with any made-up username and password. The resulting `/private` page requires a valid server-side session, as does `/api/private`.

The function issues this cookie only after successful login:

```http
Set-Cookie: __Host-safari_poc_session=<random-token>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

Sessions use Netlify Blobs with strong consistency so they survive separate function instances. No manually configured secret or API token is required in the hosted function. There is no server-side session timeout. Sign out deletes the session. The browser cookie has a one-year persistence lifetime; clearing site data, browser privacy policies or cookie expiry can still require another sign-in. Sign in again after upgrading from the old ten-minute version to replace its short-lived cookie.

1. Sign in while Safari is unlocked and leave `/private?test=private-lock-001` selected.
2. Background Safari and let the relevant lock engage. Test app lock and Private Browsing lock separately.
3. Wait 30 seconds without touching Safari to establish a baseline.
4. Tap Safari without passing Face ID.
5. In the Netlify `poc` function logs, look for a new `SAFARI_LOGIN_POC` entry with the private URL, a fresh timestamp and `"authenticated":true`.
6. A recorded response containing the session's `FAKE-PRIVATE-...` marker demonstrates synthetic private content was returned. It does not demonstrate UI display or JavaScript execution.

The logs intentionally include this demo's session cookie, never the submitted password. Log retention is separate from session expiry. HTTPS encrypts requests in transit: function logs prove receipt by the site, not readability by an arbitrary Wi-Fi observer. HTTPS interception still requires the appropriate trust setup.

Netlify installs the pinned dependency, checks the function and bundles it with esbuild. Only `public/` is published as static content; source files and local logs are not static website files. Root and app routes are rewritten to the function.

## Local HTTP login demo

The local `server.js` provides a real server-side demo login:

- Username and password: any non-empty made-up values.
- Cookie: `safari_poc_session` (random, HttpOnly, SameSite=Lax)
- No server-side session timeout. The browser cookie persists for up to one year.
- The command-line server saves sessions in `.data/sessions.json`; restarting preserves
  sessions. This directory is ignored by Git and is never served over HTTP.
- The username is saved in the JSON session; the password is not stored.
- `/private` and `/api/private` require a valid session and return only synthetic data.
- Sign out invalidates the session, including copied cookies.

Start it with Node.js:

```bash
node server.js
```

The local server also supports `/?url=...` with the same destination restrictions.
Tests use isolated in-memory sessions unless
a JSON session filename is explicitly supplied.

Open `http://<your-computer-wifi-ip>:8080/?test=locked-lan-001` on your iPhone, sign in, and leave the resulting `/private` tab selected. Keep the iPhone and computer on the same network. Disable the Wi-Fi proxy for this direct HTTP demonstration.

### Locked Safari reproduction

1. Sign in while Safari is unlocked; confirm the private page appears.
2. Return to Home and let the app or Private Browsing lock engage. Test each lock separately.
3. Start a fresh packet capture on the computer's Wi-Fi interface, filtered with `tcp.port == 8080`.
4. Wait 30 seconds without opening Safari to establish a quiet baseline.
5. Tap Safari without passing Face ID, then check for fresh `GET /private` traffic.
6. The server prints `Auth: AUTHENTICATED <username>` only if that request contains a valid session cookie. Verify the timestamp against the still-visible lock prompt.
7. A fresh HTTP 200 response containing `FAKE-PRIVATE-...` establishes that synthetic private content was returned. It does not establish UI display or JavaScript execution.

The local demo deliberately omits the cookie's Secure attribute to permit HTTP transmission. Use fake data and made-up credentials only; this is not production authentication. Login passwords are not printed, but demo session cookies and URLs are deliberately logged. Log retention and session expiry are different: logs are not automatically deleted after 10 minutes.

To check the demo cookie's authority from a separate client while it is valid, send that demo cookie to `/api/private`. Requests without it return HTTP 401. This demonstrates the behavior of this custom app, not account compromise on another website.

Capturing on the computer hosting the server demonstrates readable traffic at that endpoint. Observing it as a third party requires an appropriate network position; sharing Wi-Fi alone is insufficient. HTTPS traffic remains encrypted even on a local network.

The Netlify HTTPS login uses a separate Secure cookie and persistent session store. Local HTTP and Netlify sessions are independent.

### Verification

```bash
npm install
npm test
```

