const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");

function getJwtSecret() {
  const secret = process.env.JWTSECRET;
  if (!secret) throw new Error("JWTSECRET environment variable is not set");
  return secret;
}

function signToken(payload) {
  return jwt.sign(
    { id: payload.id, email: payload.email },
    getJwtSecret(),
    { expiresIn: "1h", jwtid: crypto.randomUUID() }
  );
}

function verifyToken(token) {
  return jwt.verify(token, getJwtSecret());
}

module.exports = { signToken, verifyToken };
