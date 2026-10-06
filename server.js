const http = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 8080;

function parseCookies(header) {
  return Object.fromEntries(
    (header || "")
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        if (index === -1) return [part, ""];
        return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
      })
  );
}

function htmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function requestUrl(req) {
  const host = req.headers.host || "localhost";
  return `http://${host}${req.url}`;
}

function logRequest(req) {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  console.log(`Host: ${req.headers.host || ""}`);
  console.log(`Cookie: ${req.headers.cookie || "(none)"}`);
  console.log("");
}

const server = http.createServer((req, res) => {
  logRequest(req);

  const existingCookies = parseCookies(req.headers.cookie);
  const visitId = existingCookies.safari_lock_poc || crypto.randomBytes(8).toString("hex");
  const setCookie = [
    `safari_lock_poc=${encodeURIComponent(visitId)}`,
    "Path=/",
    "SameSite=Lax",
    "Max-Age=86400",
  ].join("; ");

  if (req.url.startsWith("/pixel")) {
    res.writeHead(204, {
      "Set-Cookie": setCookie,
      "Cache-Control": "no-store",
    });
    res.end();
    return;
  }

  if (req.url.startsWith("/clear")) {
    res.writeHead(302, {
      "Set-Cookie": "safari_lock_poc=deleted; Path=/; Max-Age=0; SameSite=Lax",
      Location: "/?cleared=1",
      "Cache-Control": "no-store",
    });
    res.end();
    return;
  }

  const cookieHeader = req.headers.cookie || "(none)";
  const fullUrl = requestUrl(req);

  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Set-Cookie": setCookie,
    "Cache-Control": "no-store",
  });

  res.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Safari Lock Cookie PoC</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f6f7f9;
      color: #17202a;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      box-sizing: border-box;
    }

    main {
      width: min(680px, 100%);
      background: #ffffff;
      border: 1px solid #d9dee7;
      border-radius: 8px;
      padding: 24px;
      box-shadow: 0 14px 40px rgba(23, 32, 42, 0.08);
    }

    h1 {
      margin: 0 0 8px;
      font-size: 24px;
      line-height: 1.2;
    }

    p {
      line-height: 1.55;
    }

    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #f0f3f7;
      border: 1px solid #d9dee7;
      border-radius: 6px;
      padding: 14px;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }

    a, button {
      border: 1px solid #1f6feb;
      background: #1f6feb;
      color: #fff;
      border-radius: 6px;
      padding: 10px 14px;
      font: inherit;
      text-decoration: none;
      cursor: pointer;
    }

    a.secondary {
      background: transparent;
      color: #1f6feb;
    }

    @media (prefers-color-scheme: dark) {
      :root {
        background: #111418;
        color: #e8edf5;
      }

      main {
        background: #181d24;
        border-color: #303846;
      }

      pre {
        background: #111418;
        border-color: #303846;
      }
    }
  </style>
</head>
<body>
  <main>
    <h1>Safari Lock Cookie PoC</h1>
    <p>This page sets <code>safari_lock_poc</code> with <code>Set-Cookie</code>. Reopen this same URL through locked Safari and check whether Burp sees the cookie before Face ID unlock.</p>

    <p><strong>Current request URL</strong></p>
    <pre>${htmlEscape(fullUrl)}</pre>

    <p><strong>Cookie header received by server</strong></p>
    <pre>${htmlEscape(cookieHeader)}</pre>

    <p><strong>Cookie value assigned for this browser</strong></p>
    <pre>safari_lock_poc=${htmlEscape(visitId)}</pre>

    <div class="actions">
      <button type="button" onclick="location.reload()">Reload</button>
      <a class="secondary" href="/?para=poc&token=demo-secret-${htmlEscape(visitId)}">Open token URL</a>
      <a class="secondary" href="/clear">Clear cookie</a>
    </div>
  </main>
  <img src="/pixel?ts=${Date.now()}" alt="" width="1" height="1">
</body>
</html>`);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Cookie PoC running at http://localhost:${PORT}`);
  console.log("Open it from your iPhone with your computer's LAN IP, for example:");
  console.log(`http://<your-computer-ip>:${PORT}/?para=poc`);
});
