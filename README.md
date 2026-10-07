# Safari Session PoC

Demo login for checking whether locked Safari restores a selected tab and sends an authenticated request before app-lock or Private Browsing authentication. Both versions use public demo credentials and synthetic data only.

## Netlify HTTPS login

Open https://safari-poc.netlify.app/?test=private-lock-001 and sign in with username `demo` and password `demo1234`. The resulting `/private` page requires a valid server-side session, as does `/api/private`.

The function issues this cookie only after successful login:

```http
Set-Cookie: __Host-safari_poc_session=<random-token>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

Sessions use Netlify Blobs with strong consistency so they survive separate function instances. No manually configured secret or API token is required in the hosted function. Sessions expire 10 minutes after login; reads do not extend expiry. Sign out deletes the session. Expired records are deleted when accessed.

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

- Username: `demo`
- Password: `demo1234`
- Cookie: `safari_poc_session` (random, HttpOnly, SameSite=Lax)
- Session lifetime: 10 minutes from login; requests do not renew it.
- Sessions are kept in memory. Restarting the server logs everyone out.
- `/private` and `/api/private` require a valid session and return only synthetic data.
- Sign out invalidates the session, including copied cookies.

Start it with Node.js:

```bash
node server.js
```

Open `http://<your-computer-wifi-ip>:8080/?test=locked-lan-001` on your iPhone, sign in, and leave the resulting `/private` tab selected. Keep the iPhone and computer on the same network. Disable the Wi-Fi proxy for this direct HTTP demonstration.

### Locked Safari reproduction

1. Sign in while Safari is unlocked; confirm the private page appears.
2. Return to Home and let the app or Private Browsing lock engage. Test each lock separately.
3. Start a fresh packet capture on the computer's Wi-Fi interface, filtered with `tcp.port == 8080`.
4. Wait 30 seconds without opening Safari to establish a quiet baseline.
5. Tap Safari without passing Face ID, then check for fresh `GET /private` traffic.
6. The server prints `Auth: AUTHENTICATED demo` only if that request contains a valid session cookie. Verify the timestamp against the still-visible lock prompt.
7. A fresh HTTP 200 response containing `FAKE-PRIVATE-...` establishes that synthetic private content was returned. It does not establish UI display or JavaScript execution.

The local demo deliberately omits the cookie's Secure attribute to permit HTTP transmission. Use fake data and these public demo credentials only; this is not production authentication. Login passwords are not printed, but demo session cookies and URLs are deliberately logged. Log retention and session expiry are different: logs are not automatically deleted after 10 minutes.

To check the demo cookie's authority from a separate client while it is valid, send that demo cookie to `/api/private`. Requests without it return HTTP 401. This demonstrates the behavior of this custom app, not account compromise on another website.

Capturing on the computer hosting the server demonstrates readable traffic at that endpoint. Observing it as a third party requires an appropriate network position; sharing Wi-Fi alone is insufficient. HTTPS traffic remains encrypted even on a local network.

The Netlify HTTPS login uses a separate Secure cookie and persistent session store. Local HTTP and Netlify sessions are independent.

### Verification

```bash
npm install
npm test
```

