const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHandler, SESSION_COOKIE } = require("../lib/netlify-app");
const { SESSION_TTL_MS } = require("../server");

function fixture() {
  let time = Date.UTC(2026, 9, 7);
  const records = new Map();
  const logs = [];
  const store = {
    async get(key, options) { assert.equal(options.type, "json"); return records.get(key) || null; },
    async setJSON(key, value) { records.set(key, structuredClone(value)); },
    async delete(key) { records.delete(key); },
  };
  const freshHandler = () => createHandler({ getStoreForEvent: () => store, now: () => time, log: (value) => logs.push(value) });
  const call = (path, options = {}, handler = freshHandler()) => handler({
    httpMethod: options.method || "GET", rawUrl: `https://safari-poc.netlify.app${path}`,
    headers: { host: "safari-poc.netlify.app", ...options.headers },
    body: options.body || "", isBase64Encoded: Boolean(options.base64),
  });
  const login = (options = {}) => call("/login", {
    method: "POST", headers: { origin: "https://safari-poc.netlify.app", ...options.headers },
    body: new URLSearchParams({ username: "demo", password: "demo1234", ...options.fields }).toString(),
  });
  return { call, login, records, logs, freshHandler, advance: (amount) => { time += amount; } };
}

test("Netlify guests and forged cookies cannot read private data", async () => {
  const { call } = fixture();
  for (const path of ["/private", "/api/private"]) {
    for (const headers of [{}, { cookie: `${SESSION_COOKIE}=${"a".repeat(64)}` }]) {
      const result = await call(path, { headers });
      assert.equal(result.statusCode, 401);
      assert.doesNotMatch(result.body, /FAKE-PRIVATE-/);
      assert.match(result.headers["Cache-Control"], /no-store/);
    }
  }
});

test("Netlify login survives separate handler instances and uses an HTTPS-only cookie", async () => {
  const { login, call, records, logs } = fixture();
  const result = await login({ fields: { next: "/private?test=private-lock-001" } });
  assert.equal(result.statusCode, 303);
  assert.equal(result.headers.Location, "/private?test=private-lock-001");
  assert.match(result.headers["Set-Cookie"], /^__Host-safari_poc_session=[a-f0-9]{64}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/);
  const cookie = result.headers["Set-Cookie"].split(";")[0];
  assert.notEqual([...records.keys()][0], cookie.split("=")[1]);
  const result2 = await call("/private?test=private-lock-001", { headers: { cookie } });
  assert.equal(result2.statusCode, 200);
  const marker = result2.body.match(/FAKE-PRIVATE-[a-f0-9]{24}/)[0];
  const api = await call("/api/private", { headers: { cookie } });
  assert.equal(JSON.parse(api.body).privateMarker, marker);
  assert.equal(api.headers["Set-Cookie"], undefined);
  assert.match(logs.join("\n"), /"authenticated":true/);
  assert.doesNotMatch(logs.join("\n"), /demo1234/);
});

test("Netlify session expires without renewal", async () => {
  const { login, call, advance, records } = fixture();
  const result = await login();
  const headers = { cookie: result.headers["Set-Cookie"].split(";")[0] };
  advance(SESSION_TTL_MS - 1);
  assert.equal((await call("/api/private", { headers })).statusCode, 200);
  advance(1);
  const expired = await call("/api/private", { headers });
  assert.equal(expired.statusCode, 401);
  assert.match(expired.headers["Set-Cookie"], /Max-Age=0/);
  assert.equal(records.size, 0);
});

test("Netlify logout deletes the session for all handler instances", async () => {
  const { login, call, records } = fixture();
  const result = await login();
  const headers = { cookie: result.headers["Set-Cookie"].split(";")[0] };
  const html = (await call("/private", { headers })).body;
  const csrf = html.match(/name="csrf" value="([a-f0-9]+)"/)[1];
  const rejected = await call("/logout", { method: "POST", headers, body: "csrf=wrong" });
  assert.equal(rejected.statusCode, 403);
  assert.equal(records.size, 1);
  const logout = await call("/logout", { method: "POST", headers, body: `csrf=${csrf}` });
  assert.equal(logout.statusCode, 303);
  assert.equal(records.size, 0);
  assert.equal((await call("/api/private", { headers })).statusCode, 401);
});

test("Netlify rejects bad credentials, cross-site login, oversized forms and external redirects", async () => {
  const { login, call } = fixture();
  const bad = await login({ fields: { password: "wrong" } });
  assert.equal(bad.statusCode, 401);
  assert.equal(bad.headers["Set-Cookie"], undefined);
  assert.equal((await login({ headers: { origin: "https://example.com" } })).statusCode, 403);
  assert.equal((await login({ fields: { next: "//example.com/" } })).headers.Location, "/private");
  assert.equal((await call("/login", { method: "POST", body: "x".repeat(8193) })).statusCode, 413);
  const base64 = await call("/login", {
    method: "POST", body: Buffer.from("username=demo&password=demo1234").toString("base64"), base64: true,
  });
  assert.equal(base64.statusCode, 303);
});

test("Netlify storage failure refuses access instead of falling back to an insecure cookie", async () => {
  const handler = createHandler({ getStoreForEvent: () => { throw new Error("Unavailable"); }, log: () => {} });
  const result = await handler({ httpMethod: "GET", rawUrl: "https://safari-poc.netlify.app/", headers: {} });
  assert.equal(result.statusCode, 503);
  assert.equal(result.headers["Set-Cookie"], undefined);
});
