const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs/promises");
const { BlobsServer } = require("@netlify/blobs/server");
const { setEnvironmentContext } = require("@netlify/blobs");

test("Netlify v2 handler logs in and revokes sessions through the real Blobs SDK", async () => {
  const scratch = path.resolve(__dirname, "../../../work");
  await fs.mkdir(scratch, { recursive: true });
  const directory = await fs.mkdtemp(path.join(scratch, "poc-blobs-"));
  const blobs = new BlobsServer({ directory, token: "synthetic-storage-token", logger: () => {} });
  const address = await blobs.start();
  const localURL = `http://127.0.0.1:${address.port}`;
  setEnvironmentContext({
    siteID: "synthetic-site", token: "synthetic-storage-token",
    edgeURL: localURL, uncachedEdgeURL: localURL,
  });
  try {
    const { default: handler } = await import("../netlify/functions/poc.mjs");
    const base = "https://safari-poc.netlify.app";
    const login = await handler(new Request(`${base}/login`, {
      method: "POST", headers: { Origin: base },
      body: new URLSearchParams({ username: "demo", password: "demo1234" }),
    }));
    assert.equal(login.status, 303);
    const cookie = login.headers.get("set-cookie").split(";")[0];
    const privatePage = await handler(new Request(`${base}/private`, { headers: { Cookie: cookie } }));
    assert.equal(privatePage.status, 200);
    const html = await privatePage.text();
    assert.match(html, /FAKE-PRIVATE-/);
    const csrf = html.match(/name="csrf" value="([a-f0-9]+)"/)[1];
    const pixel = await handler(new Request(`${base}/pixel`, { headers: { Cookie: cookie } }));
    assert.equal(pixel.status, 204);
    assert.equal(await pixel.text(), "");
    const logout = await handler(new Request(`${base}/logout`, {
      method: "POST", headers: { Cookie: cookie, Origin: base }, body: new URLSearchParams({ csrf }),
    }));
    assert.equal(logout.status, 303);
    const rejected = await handler(new Request(`${base}/api/private`, { headers: { Cookie: cookie } }));
    assert.equal(rejected.status, 401);
  } finally {
    setEnvironmentContext({});
    await blobs.stop();
  }
});
