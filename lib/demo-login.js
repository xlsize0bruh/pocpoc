function validLogin(username, password) {
  return typeof username === "string" && username.trim().length > 0 && username.length <= 80 &&
    !/[\x00-\x1f\x7f]/.test(username) && typeof password === "string" &&
    password.trim().length > 0 && password.length <= 256;
}

module.exports = { validLogin };
