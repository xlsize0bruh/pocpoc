const crypto = require("node:crypto");
const { DEMO_USER, DEMO_PASSWORD, SESSION_TTL_MS, page, escapeHtml, cookieValue } = require("../server");
const { validLogin } = require("./demo-login");
const { createCallbackSender, MESSAGE } = require("./callback");

const SESSION_COOKIE = "__Host-safari_poc_session";
const STORE_NAME = "safari-demo-sessions-v1";

function netlifyStore() {
  const { getStore } = require("@netlify/blobs");
  return getStore({ name: STORE_NAME, consistency: "strong" });
}

function sessionKey(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createHandler({ getStoreForEvent = netlifyStore, now = Date.now, log = console.log, sendCallback = createCallbackSender() } = {}) {
  return async (event) => {
    const headers = {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      Pragma: "no-cache", Expires: "0",
      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    };
    const response = (statusCode, body, type) => ({ statusCode, headers: type ? { ...headers, "Content-Type": type } : { ...headers }, body });
    const redirect = (target) => {
      headers.Location = target;
      return response(303, "");
    };
    const clearCookie = () => { headers["Set-Cookie"] = `${SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`; };
    try {
      const incoming = Object.fromEntries(Object.entries(event.headers || {}).map(([key, value]) => [key.toLowerCase(), value]));
      const url = new URL(event.rawUrl || `https://${incoming.host || "safari-poc.netlify.app"}${event.path || "/"}${event.rawQuery ? `?${event.rawQuery}` : ""}`);
      const route = url.pathname === "/.netlify/functions/poc" ? "/" : url.pathname;
      const method = event.httpMethod || "GET";
      const time = now();
      const token = cookieValue(incoming.cookie, SESSION_COOKIE);
      const store = getStoreForEvent(event);
      const key = /^[a-f0-9]{64}$/.test(token) ? sessionKey(token) : null;
      const record = key ? await store.get(key, { type: "json" }) : null;
      const session = record && record.expiresAt > time ? record : null;
      if (record && !session) await store.delete(key);
      if (token && !session) clearCookie();
      log("SAFARI_LOGIN_POC " + JSON.stringify({
        time: new Date(time).toISOString(), method, path: `${route}${url.search}`,
        authenticated: Boolean(session), account: session ? DEMO_USER : null,
        sessionCookie: token ? `${SESSION_COOKIE}=${token}` : "(none)",
        userAgent: incoming["user-agent"] || "",
      }));

      const loginPage = (error = "", next = "/private", status = 200) => response(status, page("Sign in", `
        <h1>Sign in</h1>${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}
        <form method="post" action="/login"><input type="hidden" name="next" value="${escapeHtml(next)}">
          <label for="username">Username</label><input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>
          <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
          <button type="submit">Sign in</button></form>
        <p class="credentials">Demo credentials: <code>demo</code> / <code>demo1234</code></p>`));

      if (method === "POST" && ["/login", "/logout"].includes(route)) {
        if ((incoming.origin && incoming.origin !== url.origin) || incoming["sec-fetch-site"] === "cross-site") {
          return response(403, page("Request blocked", "<h1>Request blocked</h1><p>Open the form directly on this site.</p>"));
        }
        const body = event.isBase64Encoded ? Buffer.from(event.body || "", "base64").toString("utf8") : event.body || "";
        if (Buffer.byteLength(body) > 8192) return response(413, "Form too large", "text/plain; charset=utf-8");
        const form = new URLSearchParams(body);
        if (route === "/logout") {
          if (!session || form.get("csrf") !== session.csrf) return response(403, page("Request blocked", "<h1>Request blocked</h1>"));
          await store.delete(key);
          clearCookie();
          return redirect("/login?loggedout=1");
        }
        const candidate = form.get("next") || "/private";
        const next = candidate === "/private" || candidate.startsWith("/private?") ? candidate : "/private";
        if (!validLogin(form.get("username"), form.get("password"))) return loginPage("Incorrect username or password.", next, 401);
        const freshToken = crypto.randomBytes(32).toString("hex");
        if (session) await store.delete(key);
        await store.setJSON(sessionKey(freshToken), {
          expiresAt: time + SESSION_TTL_MS, csrf: crypto.randomBytes(24).toString("hex"),
          privateMarker: `FAKE-PRIVATE-${crypto.randomBytes(12).toString("hex")}`,
        });
        headers["Set-Cookie"] = `${SESSION_COOKIE}=${freshToken}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`;
        return redirect(next);
      }
      if (method !== "GET") {
        headers.Allow = ["/login", "/logout"].includes(route) ? "GET, POST" : "GET";
        return response(405, "Method not allowed", "text/plain; charset=utf-8");
      }
      if (route === "/favicon.ico") return response(204, "");
      if (route === "/login") return session ? redirect("/private") : loginPage(record ? "Session expired. Sign in again." : "");
      if (route === "/" && url.searchParams.has("url")) {
        if (!session) return loginPage("Sign in first. No callback was sent.", "/private", 401);
        try {
          await sendCallback(url.searchParams.get("url"));
          log("SAFARI_CALLBACK_POC " + JSON.stringify({ time: new Date(now()).toISOString(), authenticated: true, sent: true }));
          return response(200, page("Ping sent", `<h1>Ping sent</h1><pre>${escapeHtml(MESSAGE)}</pre><a href="/private">Account</a>`));
        } catch (error) {
          return response(error.status || 502, page("Ping failed", `<h1>Ping failed</h1><p role="alert">${escapeHtml(error.message)}</p><a href="/private">Account</a>`));
        }
      }
      if (route === "/") return session ? redirect(`/private${url.search}`) : loginPage("", `/private${url.search}`);
      if (route === "/api/private") return response(session ? 200 : 401, JSON.stringify(session ? {
        account: DEMO_USER, privateMarker: session.privateMarker,
        expiresAt: new Date(session.expiresAt).toISOString(), synthetic: true,
      } : { error: "Authentication required" }), "application/json; charset=utf-8");
      if (route === "/pixel") return response(session ? 204 : 401, "");
      if (["/private", "/clear", "/logout"].includes(route)) {
        if (!session) return loginPage(record ? "Session expired. Sign in again." : "Sign in to access this page.", `/private${url.search}`, 401);
        return response(200, page("Private account", `
          <h1>Private account</h1><p class="status">Signed in as demo</p>
          <dl><div><dt>Account</dt><dd>Demo user</dd></div>
          <div><dt>Private marker</dt><dd><code>${escapeHtml(session.privateMarker)}</code></dd></div>
          <div><dt>Session expires</dt><dd>${escapeHtml(new Date(session.expiresAt).toISOString())}</dd></div>
          <div><dt>Session ID</dt><dd><code>${escapeHtml(token.slice(0, 12))}...</code></dd></div></dl>
          <h2>Current request</h2><pre>${escapeHtml(`${method} ${route}${url.search}\nHost: ${url.host}\nAuth: AUTHENTICATED demo`)}</pre>
          <h2>Callback</h2><form method="get" action="/">
          <label for="callback">Callback URL</label><input id="callback" type="url" name="url" placeholder="https://your-endpoint.example/" required>
          <button type="submit">Send ping</button></form>
          <div class="actions"><a href="${escapeHtml(`/private${url.search}`)}">Reload account</a>
          <a href="/api/private">Account JSON</a>
          <form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(session.csrf)}"><button type="submit">Sign out</button></form></div>
          <img src="/pixel?ts=${time}" alt="" width="1" height="1">`));
      }
      return response(404, page("Not found", '<h1>Not found</h1><a href="/">Open account</a>'));
    } catch (error) {
      log("SAFARI_LOGIN_POC_ERROR " + error.message);
      const errorCode = error.code || error.name || "STORAGE_ERROR";
      return response(503, page("Temporarily unavailable", `<h1>Temporarily unavailable</h1><p>Demo session storage is unavailable. Try again shortly.</p><p>Error code: <code>${escapeHtml(errorCode)}</code></p>`));
    }
  };
}

exports.handler = createHandler();
exports.createHandler = createHandler;
exports.SESSION_COOKIE = SESSION_COOKIE;
