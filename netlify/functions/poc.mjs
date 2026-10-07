import app from "../../lib/netlify-app.js";

export default async function handler(request) {
  const result = await app.handler({
    httpMethod: request.method,
    rawUrl: request.url,
    headers: Object.fromEntries(request.headers),
    body: ["GET", "HEAD"].includes(request.method) ? "" : await request.text(),
    isBase64Encoded: false,
  });
  return new Response(result.statusCode === 204 ? null : result.body, {
    status: result.statusCode,
    headers: result.headers,
  });
}
