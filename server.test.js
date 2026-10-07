const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createPocServer, SESSION_TTL_MS } = require("./server");

async function fixture(t, options = {}) {
  let time = Date.UTC(2026, 9, 7);
  const logs = [];
  const server = createPocServer({ now: () => time, log: (line) => logs.push(line), ...options });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  }));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (path, options = {}) => fetch(`${base}${path}`, { redirect: "manual", ...options });
  const login = (password = "demo1234", next = "/private", username = "demo") => request("/login", {
    method: "POST", headers: { Origin: base },
    body: new URLSearchParams({ username, password, next }),
  });
  return { request, login, logs, advance: (amount) => { time += amount; } };
}

test("guests and forged sessions cannot read the private HTML or JSON", async (t) => {
  const { request } = await fixture(t);
  for (const path of ["/private", "/api/private"]) {
    for (const headers of [{}, { Cookie: "safari_poc_session=forged" }]) {
      const response = await request(path, { headers });
      assert.equal(response.status, 401);
      assert.doesNotMatch(await response.text(), /FAKE-PRIVATE-/);
      assert.match(response.headers.get("cache-control"), /no-store/);
    }
  }
});

test("local callback is login-gated and logout revokes callback access", async (t) => {
  const callbacks = [];
  const { login, request } = await fixture(t, { sendCallback: async (url) => callbacks.push(url) });
  const target = "https://callback.example/locked-001";
  const route = `/?url=${encodeURIComponent(target)}`;
  assert.equal((await request(route)).status, 401);
  assert.equal((await request(route, { headers: { Cookie: "safari_poc_session=forged" } })).status, 401);
  assert.deepEqual(callbacks, []);
  const signedIn = await login();
  const headers = { Cookie: signedIn.headers.get("set-cookie").split(";")[0] };
  assert.equal((await request(route, { headers })).status, 200);
  assert.deepEqual(callbacks, [target]);
  const html = await (await request("/private", { headers })).text();
  const csrf = html.match(/name="csrf" value="([a-f0-9]+)"/)[1];
  await request("/logout", { method: "POST", headers, body: new URLSearchParams({ csrf }) });
  assert.equal((await request(route, { headers })).status, 401);
  assert.deepEqual(callbacks, [target]);
});

test("blank credentials do not create a session", async (t) => {
  const { login, logs } = await fixture(t);
  const response = await login("");
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("set-cookie"), null);
  assert.doesNotMatch(logs.join("\n"), /demo1234/);
});

test("local arbitrary sign-ins use each session's username in callbacks", async (t) => {
  const callbacks = [];
  const { login, request, logs } = await fixture(t, { sendCallback: async (url, username) => callbacks.push({ url, username }) });
  for (const username of ["alice", "bob <test>"]) {
    const signedIn = await login("any-dummy-password", "/private", username);
    assert.equal(signedIn.status, 303);
    const headers = { Cookie: signedIn.headers.get("set-cookie").split(";")[0] };
    assert.equal((await (await request("/api/private", { headers })).json()).account, username);
    const ping = await request("/?url=https%3A%2F%2Fcallback.example%2F&username=spoofed", { headers });
    assert.equal(ping.status, 200);
    const html = await ping.text();
    assert.match(html, /Username:/);
    assert.doesNotMatch(html, /bob <test>/);
    assert.deepEqual(callbacks.at(-1), { url: "https://callback.example/", username });
  }
  assert.doesNotMatch(logs.join("\n"), /any-dummy-password/);
});

test("login gates synthetic data with a reusable, stable session cookie", async (t) => {
  const { login, request, logs } = await fixture(t);
  const response = await login();
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/private");
  const setCookie = response.headers.get("set-cookie");
  assert.match(setCookie, /^safari_poc_session=[a-f0-9]{64};/);
  assert.match(setCookie, /HttpOnly; SameSite=Lax; Max-Age=600/);
  assert.doesNotMatch(setCookie, /Secure/);
  const headers = { Cookie: setCookie.split(";")[0] };
  const privatePage = await request("/private?test=locked-lan-001", { headers });
  assert.equal(privatePage.status, 200);
  assert.equal(privatePage.headers.get("set-cookie"), null);
  const html = await privatePage.text();
  const marker = html.match(/FAKE-PRIVATE-[a-f0-9]{24}/)[0];
  const api = await request("/api/private", { headers });
  assert.equal(api.status, 200);
  assert.equal((await api.json()).privateMarker, marker);
  assert.equal((await request("/pixel", { headers })).status, 204);
  assert.match(logs.join("\n"), /Auth: AUTHENTICATED demo/);
});

test("requests do not extend expiry and an expired copied cookie is rejected", async (t) => {
  const { login, request, advance } = await fixture(t);
  const response = await login();
  const headers = { Cookie: response.headers.get("set-cookie").split(";")[0] };
  advance(SESSION_TTL_MS - 1);
  assert.equal((await request("/api/private", { headers })).status, 200);
  advance(1);
  assert.equal((await request("/api/private", { headers })).status, 401);
});

test("logout requires its form token and invalidates the copied session", async (t) => {
  const { login, request } = await fixture(t);
  const response = await login();
  const headers = { Cookie: response.headers.get("set-cookie").split(";")[0] };
  const html = await (await request("/private", { headers })).text();
  const csrf = html.match(/name="csrf" value="([a-f0-9]+)"/)[1];
  const invalidLogout = await request("/logout", {
    method: "POST", headers, body: new URLSearchParams({ csrf: "wrong" }),
  });
  assert.equal(invalidLogout.status, 403);
  assert.equal((await request("/api/private", { headers })).status, 200);
  const logout = await request("/logout", {
    method: "POST", headers, body: new URLSearchParams({ csrf }),
  });
  assert.equal(logout.status, 303);
  assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);
  assert.equal((await request("/api/private", { headers })).status, 401);
});

test("login rejects foreign origins and preserves only private local redirects", async (t) => {
  const { request, login } = await fixture(t);
  const foreign = await request("/login", {
    method: "POST", headers: { Origin: "https://example.com" },
    body: new URLSearchParams({ username: "demo", password: "demo1234" }),
  });
  assert.equal(foreign.status, 403);
  const response = await login("demo1234", "//example.com/");
  assert.equal(response.headers.get("location"), "/private");
  const withQuery = await login("demo1234", "/private?test=locked-lan-001");
  assert.equal(withQuery.headers.get("location"), "/private?test=locked-lan-001");
});
