const http = require("node:http");
const crypto = require("node:crypto");
const path = require("node:path");
const { validLogin } = require("./lib/demo-login");
const { createCallbackSender, MESSAGE } = require("./lib/callback");
const { JsonSessions } = require("./lib/json-sessions");

const SESSION_COOKIE = "safari_poc_session";
const SESSION_TTL_MS = 10 * 60 * 1000;
const DEMO_USER = "demo";
const DEMO_PASSWORD = "demo1234";

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function cookieValue(header, name) {
  const entry = (header || "").split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return entry ? entry.slice(name.length + 1) : "";
}

function page(title, content) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} | Safari Session PoC</title>
<style>
  :root { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #20252b; background: #f5f7f8; }
  * { box-sizing: border-box; }
  body { margin: 0; }
  header { background: #fff; border-bottom: 1px solid #dce1e6; padding: 18px 24px; font-weight: 650; }
  header span { color: #606b75; font-size: 12px; margin-left: 12px; font-weight: 400; }
  main { width: min(720px, 100%); margin: 36px auto; padding: 0 24px; }
  h1 { font-size: 26px; line-height: 1.2; margin: 0 0 24px; }
  h2 { font-size: 17px; margin: 28px 0 12px; }
  form { max-width: 400px; }
  label { display: block; margin: 16px 0 7px; font-size: 14px; font-weight: 600; }
  input { width: 100%; min-height: 44px; border: 1px solid #aab5bf; background: #fff; border-radius: 5px; padding: 10px 12px; font: inherit; }
  input:focus-visible, button:focus-visible, a:focus-visible { outline: 3px solid #82b8ed; outline-offset: 3px; }
  button { min-height: 44px; margin-top: 20px; background: #17633e; color: #fff; border: 0; border-radius: 5px; padding: 10px 20px; font: inherit; cursor: pointer; }
  a { color: #145ea8; overflow-wrap: anywhere; }
  .credentials { color: #5c6771; font-size: 14px; margin-top: 20px; }
  .error { color: #9d2133; background: #fff0f1; border-left: 3px solid #b52b40; padding: 12px; }
  .status { color: #17633e; margin-top: -10px; }
  dl { margin: 0; border-top: 1px solid #dce1e6; }
  dl div { display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 12px; padding: 14px 0; border-bottom: 1px solid #dce1e6; }
  dt { color: #626c76; } dd { margin: 0; overflow-wrap: anywhere; }
  code, pre { font-family: ui-monospace, Consolas, monospace; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #eaf0f4; padding: 16px; border-radius: 5px; }
  .actions { display: flex; align-items: center; flex-wrap: wrap; gap: 24px; margin-top: 24px; }
  .actions button { margin-top: 0; background: #414b55; }
  @media (max-width: 420px) { header, main { padding-left: 18px; padding-right: 18px; } header span { display: block; margin: 6px 0 0; } dl div { grid-template-columns: 1fr; gap: 6px; } }
</style></head><body>
<header>Safari Session PoC <span>Demo account / synthetic data</span></header>
<main>${content}</main></body></html>`;
}

async function readForm(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size <= 8192) chunks.push(chunk);
  }
  if (size > 8192) throw Object.assign(new Error("Form too large"), { status: 413 });
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function createPocServer({ now = Date.now, log = console.log, sendCallback = createCallbackSender(), sessionFile } = {}) {
  const sessions = sessionFile ? new JsonSessions(sessionFile) : new Map();
  return http.createServer(async (req, res) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");

    const send = (status, body, type = "text/html; charset=utf-8") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(body);
    };
    const redirect = (target) => {
      res.writeHead(303, { Location: target });
      res.end();
    };
    const clearCookie = () => res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);

    try {
      const url = new URL(req.url, "http://poc.invalid");
      const time = now();
      const token = cookieValue(req.headers.cookie, SESSION_COOKIE);
      const previous = sessions.get(token);
      const session = previous && previous.expiresAt > time ? previous : null;
      for (const [key, value] of sessions) {
        if (value.expiresAt <= time) sessions.delete(key);
      }
      const authStatus = session ? "AUTHENTICATED demo" : previous ? "EXPIRED" : token ? "INVALID SESSION" : "NOT AUTHENTICATED";
      log(`[${new Date(time).toISOString()}] ${req.method} ${req.url}\nHost: ${req.headers.host || ""}\nCookie: ${token ? `${SESSION_COOKIE}=${token}` : "(none)"}\nAuth: ${authStatus}\n`);
      if (token && !session) clearCookie();

      const loginPage = (error = "", next = "/private", status = 200) => send(status, page("Sign in", `
        <h1>Sign in</h1>
        ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}
        <form method="post" action="/login">
          <input type="hidden" name="next" value="${escapeHtml(next)}">
          <label for="username">Username</label>
          <input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
          <button type="submit">Sign in</button>
        </form>
        <p class="credentials">Demo credentials: <code>demo</code> / <code>demo1234</code></p>`));

      if (req.method === "POST" && ["/login", "/logout"].includes(url.pathname)) {
        const origin = req.headers.origin;
        if ((origin && origin !== `http://${req.headers.host}`) || req.headers["sec-fetch-site"] === "cross-site") {
          send(403, page("Request blocked", "<h1>Request blocked</h1><p>Open the form directly on this site.</p>"));
          return;
        }
        const form = await readForm(req);
        if (url.pathname === "/logout") {
          if (!session || form.get("csrf") !== session.csrf) {
            send(403, page("Request blocked", "<h1>Request blocked</h1>"));
            return;
          }
          sessions.delete(token);
          clearCookie();
          redirect("/login?loggedout=1");
          return;
        }
        const candidate = form.get("next") || "/private";
        const next = candidate === "/private" || candidate.startsWith("/private?") ? candidate : "/private";
        if (!validLogin(form.get("username"), form.get("password"))) {
          loginPage("Incorrect username or password.", next, 401);
          return;
        }
        const freshToken = crypto.randomBytes(32).toString("hex");
        if (session) sessions.delete(token);
        sessions.set(freshToken, {
          expiresAt: time + SESSION_TTL_MS,
          csrf: crypto.randomBytes(24).toString("hex"),
          privateMarker: `FAKE-PRIVATE-${crypto.randomBytes(12).toString("hex")}`,
        });
        // This local HTTP demo deliberately omits Secure so its cookie travels over HTTP.
        res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${freshToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`);
        log(`[${new Date(time).toISOString()}] LOGIN SUCCESS demo (10-minute session)`);
        redirect(next);
        return;
      }

      if (req.method !== "GET") {
        res.setHeader("Allow", ["/login", "/logout"].includes(url.pathname) ? "GET, POST" : "GET");
        send(405, "Method not allowed", "text/plain; charset=utf-8");
        return;
      }
      if (url.pathname === "/favicon.ico") {
        res.writeHead(204);
        res.end();
        return;
      }
      if (url.pathname === "/login") {
        if (session) redirect("/private");
        else loginPage(previous ? "Session expired. Sign in again." : "");
        return;
      }
      if (url.pathname === "/") {
        if (url.searchParams.has("url")) {
          if (!session) {
            loginPage("Sign in first. No callback was sent.", "/private", 401);
            return;
          }
          try {
            await sendCallback(url.searchParams.get("url"));
            log(`[${new Date(now()).toISOString()}] CALLBACK SUCCESS demo`);
            send(200, page("Ping sent", `<h1>Ping sent</h1><pre>${escapeHtml(MESSAGE)}</pre><a href="/private">Account</a>`));
          } catch (error) {
            send(error.status || 502, page("Ping failed", `<h1>Ping failed</h1><p role="alert">${escapeHtml(error.message)}</p><a href="/private">Account</a>`));
          }
          return;
        }
        const next = `/private${url.search}`;
        if (session) redirect(next);
        else loginPage("", next);
        return;
      }
      if (url.pathname === "/api/private") {
        send(session ? 200 : 401, JSON.stringify(session ? {
          account: DEMO_USER, privateMarker: session.privateMarker,
          expiresAt: new Date(session.expiresAt).toISOString(), synthetic: true,
        } : { error: "Authentication required" }), "application/json; charset=utf-8");
        return;
      }
      if (url.pathname === "/pixel") {
        res.writeHead(session ? 204 : 401);
        res.end();
        return;
      }
      if (["/private", "/clear", "/logout"].includes(url.pathname)) {
        if (!session) {
          loginPage(previous ? "Session expired. Sign in again." : "Sign in to access this page.", `/private${url.search}`, 401);
          return;
        }
        send(200, page("Private account", `
          <h1>Private account</h1><p class="status">Signed in as demo</p>
          <dl><div><dt>Account</dt><dd>Demo user</dd></div>
          <div><dt>Private marker</dt><dd><code>${escapeHtml(session.privateMarker)}</code></dd></div>
          <div><dt>Session expires</dt><dd>${escapeHtml(new Date(session.expiresAt).toISOString())}</dd></div>
          <div><dt>Session ID</dt><dd><code>${escapeHtml(token.slice(0, 12))}...</code></dd></div></dl>
          <h2>Current request</h2><pre>${escapeHtml(`${req.method} ${req.url}\nHost: ${req.headers.host || ""}\nAuth: AUTHENTICATED demo`)}</pre>
          <h2>Callback</h2><form method="get" action="/">
          <label for="callback">Callback URL</label><input id="callback" type="url" name="url" placeholder="https://your-endpoint.example/" required>
          <button type="submit">Send ping</button></form>
          <div class="actions"><a href="${escapeHtml(`/private${url.search}`)}">Reload account</a>
          <a href="/api/private">Account JSON</a>
          <form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(session.csrf)}"><button type="submit">Sign out</button></form></div>
          <img src="/pixel?ts=${time}" alt="" width="1" height="1">`));
        return;
      }
      send(404, page("Not found", '<h1>Not found</h1><a href="/">Open account</a>'));
    } catch (error) {
      log(`REQUEST ERROR: ${error.message}`);
      if (!res.headersSent) send(error.status || 400, "Request could not be processed", "text/plain; charset=utf-8");
      else res.end();
    }
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT || 8080);
  createPocServer({ sessionFile: path.join(__dirname, ".data", "sessions.json") }).listen(port, "0.0.0.0", () => {
    console.log(`Safari Session PoC running at http://localhost:${port}`);
    console.log(`iPhone URL: http://<your-computer-ip>:${port}/`);
    console.log(`Demo login: ${DEMO_USER} / ${DEMO_PASSWORD}`);
    console.log("Sessions are saved in .data/sessions.json and expire after 10 minutes.");
    console.log("HTTP demo only. Use synthetic data; session cookies are intentionally logged.");
  });
}

module.exports = { createPocServer, SESSION_COOKIE, SESSION_TTL_MS, DEMO_USER, DEMO_PASSWORD, page, escapeHtml, cookieValue };
