# Safari Lock Cookie PoC

Simple page for checking whether locked Safari restores the previous tab URL and sends cookies before Safari app-lock authentication.

## Static hosting

Host `index.html` with GitHub Pages, Netlify, Vercel, Cloudflare Pages, or any static host.

Flow:

1. Open the hosted page in Safari on iPhone.
2. Tap **Open token URL**.
3. Confirm the page shows a `safari_lock_poc` cookie.
4. Close or background Safari.
5. Turn on Burp intercept.
6. Tap locked Safari but do not pass Face ID.
7. Check whether Burp sees the token URL and the `Cookie: safari_lock_poc=...` header.

## Optional Node server

If you want server-side cookie logging too:

```bash
node server.js
```

Then open:

```text
http://<your-computer-ip>:8080/?para=poc
```

The server prints each request URL and Cookie header.
