const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHandler, SESSION_COOKIE } = require("../lib/netlify-app");
const { SESSION_TTL_MS } = require("../server");

function fixture() {
  let time = Date.UTC(2026, 9, 7);
  const records = new Map();
  const logs = [];
  const callbacks = [];
  const store = {
    async get(key, options) { assert.equal(options.type, "json"); return records.get(key) || null; },
    async setJSON(key, value) { records.set(key, structuredClone(value)); },
    async delete(key) { records.delete(key); },
  };
  const freshHandler = () => createHandler({ getStoreForEvent: () => store, now: () => time, log: (value) => logs.push(value),
    sendCallback: async (url, username) => { callbacks.push({ url, username }); return { status: 200 }; } });
  const call = (path, options = {}, handler = freshHandler()) => handler({
    httpMethod: options.method || "GET", rawUrl: `https://safari-poc.netlify.app${path}`,
    headers: { host: "safari-poc.netlify.app", ...options.headers },
    body: options.body || "", isBase64Encoded: Boolean(options.base64),
  });
  const login = (options = {}) => call("/login", {
    method: "POST", headers: { origin: "https://safari-poc.netlify.app", ...options.headers },
    body: new URLSearchParams({ username: "demo", password: "demo1234", ...options.fields }).toString(),
  });
  return { call, login, records, logs, callbacks, freshHandler, advance: (amount) => { time += amount; } };
}

test("Netlify callback executes only for a valid session, not guests or expired sessions", async () => {
  const { login, call, callbacks, advance } = fixture();
  const target = "https://callback.example/unique?test=locked-001&marker=fake";
  const route = `/?url=${encodeURIComponent(target)}`;
  assert.equal((await call(route)).statusCode, 401);
  assert.equal((await call(route, { headers: { cookie: `${SESSION_COOKIE}=${"a".repeat(64)}` } })).statusCode, 401);
  assert.deepEqual(callbacks, []);
  const signedIn = await login();
  const headers = { cookie: signedIn.headers["Set-Cookie"].split(";")[0] };
  assert.deepEqual(callbacks, []);
  const ping = await call(route, { headers });
  assert.equal(ping.statusCode, 200);
  assert.match(ping.body, /This Poc by xlsize0bruh/);
  assert.deepEqual(callbacks, [{ url: target, username: "demo" }]);
  advance(SESSION_TTL_MS);
  assert.equal((await call(route, { headers })).statusCode, 401);
  assert.deepEqual(callbacks, [{ url: target, username: "demo" }]);
});

test("Netlify callback reports destination failure instead of success", async () => {
  const { login, call } = fixture();
  const signedIn = await login();
  const headers = { cookie: signedIn.headers["Set-Cookie"].split(";")[0] };
  const handler = createHandler({ getStoreForEvent: () => ({ get: async () => ({ expiresAt: Date.now() + 60000 }) }),
    sendCallback: async () => { throw Object.assign(new Error("Callback unavailable"), { status: 502 }); }, log: () => {} });
  const result = await call("/?url=https%3A%2F%2Fcallback.example", { headers }, handler);
  assert.equal(result.statusCode, 502);
  assert.match(result.body, /Ping failed/);
});

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

test("Netlify rejects blank credentials, cross-site login, oversized forms and external redirects", async () => {
  const { login, call } = fixture();
  const bad = await login({ fields: { password: "" } });
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

test("Netlify saves arbitrary usernames in JSON and never takes callback identity from the query", async () => {
  const { login, call, callbacks, records, logs } = fixture();
  for (const username of ["alice", "bob <test>"]) {
    const result = await login({ fields: { username, password: "random-dummy-password" } });
    assert.equal(result.statusCode, 303);
    const headers = { cookie: result.headers["Set-Cookie"].split(";")[0] };
    const ping = await call("/?url=https%3A%2F%2Fcallback.example%2F&username=spoofed", { headers });
    assert.equal(ping.statusCode, 200);
    assert.doesNotMatch(ping.body, /bob <test>/);
    assert.match(ping.body, username === "alice" ? /Username: alice/ : /Username: bob &lt;test&gt;/);
    assert.deepEqual(callbacks.at(-1), { url: "https://callback.example/", username });
    const api = await call("/api/private", { headers });
    assert.equal(JSON.parse(api.body).account, username);
  }
  assert.deepEqual([...records.values()].map((record) => record.username), ["alice", "bob <test>"]);
  assert.doesNotMatch(JSON.stringify([...records.values()]), /random-dummy-password|password/i);
  assert.doesNotMatch(logs.join("\n"), /random-dummy-password/);
});

test("Netlify storage failure refuses access instead of falling back to an insecure cookie", async () => {
  const handler = createHandler({ getStoreForEvent: () => { throw new Error("Unavailable"); }, log: () => {} });
  const result = await handler({ httpMethod: "GET", rawUrl: "https://safari-poc.netlify.app/", headers: {} });
  assert.equal(result.statusCode, 503);
  assert.equal(result.headers["Set-Cookie"], undefined);
});
