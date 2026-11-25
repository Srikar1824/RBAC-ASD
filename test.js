const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

process.env.JWTSECRET = "test-jwt-secret-for-unit-tests";

const { createApp } = require("./app");

function createMockPrisma() {
  let nextId = 1;
  const users = [];

  function pick(user, select) {
    if (!select) return { ...user };
    const result = {};
    for (const [key, enabled] of Object.entries(select)) {
      if (enabled) result[key] = user[key];
    }
    return result;
  }

  return {
    users,
    user: {
      async findUnique({ where, select }) {
        const found = users.find((u) =>
          where.id !== undefined ? u.id === where.id : u.email === where.email
        );
        return found ? pick(found, select) : null;
      },
      async create({ data, select }) {
        const user = {
          id: nextId++,
          email: data.email,
          password: data.password,
          name: data.name ?? null,
          createdAt: new Date(),
        };
        users.push(user);
        return pick(user, select);
      },
    },
  };
}

describe("JWT Authentication System", () => {
  let server;
  let baseUrl;
  let mockPrisma;

  before(async () => {
    mockPrisma = createMockPrisma();
    const app = createApp(mockPrisma);
    await new Promise((resolve) => {
      server = app.listen(0, "127.0.0.1", () => {
        const { port } = server.address();
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  async function request(path, options = {}) {
    const res = await fetch(`${baseUrl}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", ...options.headers },
    });
    const body = await res.json();
    return { status: res.status, body };
  }

  it("POST /signup registers a user, normalizes email, hashes password, and returns 1h JWT with jti", async () => {
    const { status, body } = await request("/signup", {
      method: "POST",
      body: JSON.stringify({ email: "  Alice@Example.COM ", password: "secret123", name: "Alice" }),
    });
    assert.equal(status, 201);
    assert.equal(body.user.email, "alice@example.com");
    assert.equal(body.user.password, undefined);
    assert.ok(body.token);
    const decoded = jwt.verify(body.token, process.env.JWTSECRET);
    assert.ok(decoded.jti);
    assert.equal(decoded.exp - decoded.iat, 3600);
    assert.equal(await bcrypt.compare("secret123", mockPrisma.users[0].password), true);
  });

  it("POST /signup rejects invalid input with 400 and duplicate email with 409", async () => {
    const shortPass = await request("/signup", {
      method: "POST",
      body: JSON.stringify({ email: "bob@example.com", password: "123" }),
    });
    assert.equal(shortPass.status, 400);
    const duplicate = await request("/signup", {
      method: "POST",
      body: JSON.stringify({ email: "ALICE@example.com", password: "password123" }),
    });
    assert.equal(duplicate.status, 409);
  });

  it("POST /login authenticates user and returns identical 401 for wrong email and wrong password", async () => {
    const ok = await request("/login", {
      method: "POST",
      body: JSON.stringify({ email: "alice@example.com", password: "secret123" }),
    });
    assert.equal(ok.status, 200);
    assert.ok(ok.body.token);
    const unknown = await request("/login", {
      method: "POST",
      body: JSON.stringify({ email: "nobody@example.com", password: "secret123" }),
    });
    const wrongPass = await request("/login", {
      method: "POST",
      body: JSON.stringify({ email: "alice@example.com", password: "wrong" }),
    });
    assert.equal(unknown.status, 401);
    assert.equal(wrongPass.status, 401);
    assert.equal(unknown.body.error, wrongPass.body.error);
  });

  it("GET /me enforces requireAuth and returns profile without password", async () => {
    const noToken = await request("/me");
    assert.equal(noToken.status, 401);
    const login = await request("/login", {
      method: "POST",
      body: JSON.stringify({ email: "alice@example.com", password: "secret123" }),
    });
    const me = await request("/me", { headers: { Authorization: `Bearer ${login.body.token}` } });
    assert.equal(me.status, 200);
    assert.equal(me.body.user.email, "alice@example.com");
    assert.equal(me.body.user.password, undefined);
  });

  it("GET /dashboard uses name when available and falls back to email", async () => {
    const login = await request("/login", {
      method: "POST",
      body: JSON.stringify({ email: "alice@example.com", password: "secret123" }),
    });
    const dash = await request("/dashboard", {
      headers: { Authorization: `Bearer ${login.body.token}` },
    });
    assert.equal(dash.status, 200);
    assert.match(dash.body.message, /Alice/);
  });
});
