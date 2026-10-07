const https = require("node:https");
const dns = require("node:dns/promises");
const { BlockList } = require("node:net");

const MESSAGE = "This Poc by xlsize0bruh";
const blocked = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
]) blocked.addSubnet(network, prefix, "ipv4");

function callbackError(message, status = 400) {
  return Object.assign(new Error(message), { status });
}

function validateTarget(value, allowedHosts = []) {
  let target;
  try { target = new URL(value); } catch { throw callbackError("Invalid callback URL."); }
  if (target.protocol !== "https:" || target.username || target.password || target.hash ||
      (target.port && target.port !== "443") || value.length > 2048) {
    throw callbackError("Use an HTTPS callback URL without credentials, fragments or a custom port.");
  }
  const allowed = allowedHosts.map((host) => host.trim().toLowerCase()).filter(Boolean);
  if (allowed.length && !allowed.includes(target.hostname)) throw callbackError("This callback host is not configured for the PoC.");
  return target;
}

function postMessage(target, address, timeoutMs) {
  return new Promise((resolve, reject) => {
    // Pin the checked IPv4 address; do not resolve again or follow redirects.
    const request = https.request(target, {
      method: "POST", agent: false, family: 4, signal: AbortSignal.timeout(timeoutMs),
      lookup: (_host, options, callback) => options.all
        ? callback(null, [{ address, family: 4 }]) : callback(null, address, 4),
      headers: { "Content-Type": "text/plain; charset=utf-8", "Content-Length": Buffer.byteLength(MESSAGE) },
    }, (response) => {
      const status = response.statusCode;
      response.destroy();
      if (status >= 200 && status < 300) resolve({ status });
      else reject(callbackError("The callback endpoint did not return a successful response.", 502));
    });
    request.on("error", () => reject(callbackError("The callback request failed or timed out.", 502)));
    request.end(MESSAGE);
  });
}

function createCallbackSender({
  allowedHosts = (process.env.CALLBACK_ALLOWED_HOSTS || "").split(","),
  resolveAddresses = (host) => dns.resolve4(host), transmit = postMessage, timeoutMs = 5000,
} = {}) {
  return async (value) => {
    const target = validateTarget(value, allowedHosts);
    let addresses;
    let timer;
    try {
      addresses = await Promise.race([
        resolveAddresses(target.hostname),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("DNS timeout")), timeoutMs); }),
      ]);
    } catch { throw callbackError("The callback hostname could not be resolved.", 502); }
    finally { clearTimeout(timer); }
    if (!addresses.length || addresses.some((ip) => !/^\d+\.\d+\.\d+\.\d+$/.test(ip) || blocked.check(ip, "ipv4"))) {
      throw callbackError("Callbacks to private or reserved networks are not allowed.");
    }
    return transmit(target, addresses[0], timeoutMs);
  };
}

module.exports = { MESSAGE, createCallbackSender, validateTarget };
