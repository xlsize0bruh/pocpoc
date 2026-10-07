const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createCallbackSender, MESSAGE } = require("../lib/callback");
const { JsonSessions } = require("../lib/json-sessions");
const { validLogin } = require("../lib/demo-login");

test("account credentials are checked against the server-only JSON hash", () => {
  assert.equal(validLogin("demo", "demo1234"), true);
  assert.equal(validLogin("demo", "wrong"), false);
  assert.equal(validLogin("other", "demo1234"), false);
  assert.equal(validLogin("demo", null), false);
});

test("callbacks require exact allowed HTTPS hosts and reject private DNS results", async () => {
  let sent = 0;
  const sender = (addresses) => createCallbackSender({ allowedHosts: ["callback.example"],
    resolveAddresses: async () => addresses, transmit: async () => { sent++; return { status: 200 }; } });
  for (const url of ["http://callback.example/", "https://other.example/", "https://callback.example.evil.test/",
    "https://user:pass@callback.example/", "https://callback.example:8080/", "https://callback.example/#fragment", "bad"]) {
    await assert.rejects(sender(["8.8.8.8"])(url));
  }
  for (const addresses of [[], ["127.0.0.1"], ["192.168.31.65"], ["169.254.169.254"], ["10.0.0.1"],
    ["100.64.0.1"], ["172.16.0.1"], ["0.0.0.0"], ["224.0.0.1"], ["::1"], ["8.8.8.8", "127.0.0.1"]]) {
    await assert.rejects(sender(addresses)("https://callback.example/"));
  }
  assert.equal(sent, 0);
});

test("callbacks pin the checked address and preserve the supplied path and query", async () => {
  const sender = createCallbackSender({ allowedHosts: ["callback.example"],
    resolveAddresses: async () => ["8.8.8.8"], transmit: async (url, address) => {
      assert.equal(url.href, "https://callback.example/a?test=private-001&marker=fake");
      assert.equal(address, "8.8.8.8");
      return { status: 204 };
    } });
  assert.deepEqual(await sender("https://callback.example/a?test=private-001&marker=fake"), { status: 204 });
  assert.equal(MESSAGE, "This Poc by xlsize0bruh");
});

test("callback DNS timeout is bounded", async () => {
  const sender = createCallbackSender({ allowedHosts: ["callback.example"], timeoutMs: 10,
    resolveAddresses: () => new Promise(() => {}), transmit: () => assert.fail("Must not transmit") });
  await assert.rejects(sender("https://callback.example/"), /could not be resolved/);
});

test("the callback URL can be supplied at request time without configuring a fixed host", async () => {
  const sent = [];
  const sender = createCallbackSender({ allowedHosts: [], resolveAddresses: async () => ["8.8.8.8"],
    transmit: async (url) => { sent.push(url.href); return { status: 200 }; } });
  await sender("https://first.example/ping");
  await sender("https://second.example/another?test=002");
  assert.deepEqual(sent, ["https://first.example/ping", "https://second.example/another?test=002"]);
});

test("JSON session records survive restarting the local store and deletion persists", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "safari-json-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "sessions.json");
  new JsonSessions(filename).set("synthetic-token", { expiresAt: 1234, csrf: "fake" });
  const reloaded = new JsonSessions(filename);
  assert.deepEqual(reloaded.get("synthetic-token"), { expiresAt: 1234, csrf: "fake" });
  reloaded.delete("synthetic-token");
  assert.equal(new JsonSessions(filename).size, 0);
});
