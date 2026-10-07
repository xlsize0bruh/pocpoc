const crypto = require("node:crypto");
const user = require("../data/demo-user.json");

function validLogin(username, password) {
  if (username !== user.username || typeof password !== "string" || password.length > 256) return false;
  const expected = Buffer.from(user.passwordHash, "hex");
  return crypto.timingSafeEqual(crypto.scryptSync(password, user.salt, expected.length), expected);
}

module.exports = { validLogin };
