require("dotenv/config");
const express = require("express");
const bcrypt = require("bcrypt");
const { prisma: defaultPrisma } = require("./db/config");
const requireAuth = require("./middleware/requireAuth");
const { signToken } = require("./utils/jwt");

const SALT_ROUNDS = 10;

function createApp(prisma = defaultPrisma) {
  const app = express();
  app.use(express.json());

  app.get("/", (req, res) => {
    res.json({
      message: "JWT Authentication API is running",
      endpoints: ["POST /signup", "POST /login", "GET /me", "GET /dashboard"],
    });
  });

  app.post("/signup", async (req, res) => {
    try {
      const { email, password, name } = req.body ?? {};

      if (typeof email !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "Email and password must be strings" });
      }

      const normalizedEmail = email.trim().toLowerCase();
      if (!normalizedEmail || password.length < 6) {
        return res.status(400).json({
          error: "Valid email and password of at least 6 characters are required",
        });
      }

      if (name !== undefined && name !== null && typeof name !== "string") {
        return res.status(400).json({ error: "Name must be a string" });
      }

      const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });
      if (existingUser) {
        return res.status(409).json({ error: "Email already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      const user = await prisma.user.create({
        data: {
          email: normalizedEmail,
          password: hashedPassword,
          name: typeof name === "string" ? name.trim() || null : null,
        },
        select: { id: true, email: true, name: true, createdAt: true },
      });

      const token = signToken({ id: user.id, email: user.email });
      return res.status(201).json({ user, token });
    } catch (error) {
      console.error("Signup error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body ?? {};

      if (typeof email !== "string" || typeof password !== "string" || !email.trim() || !password) {
        return res.status(400).json({ error: "Email and password are required" });
      }

      const normalizedEmail = email.trim().toLowerCase();
      const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

      if (!user) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      const passwordMatches = await bcrypt.compare(password, user.password);
      if (!passwordMatches) {
        return res.status(401).json({ error: "Invalid email or password" });
      }

      const token = signToken({ id: user.id, email: user.email });
      return res.status(200).json({
        user: { id: user.id, email: user.email, name: user.name, createdAt: user.createdAt },
        token,
      });
    } catch (error) {
      console.error("Login error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/me", requireAuth, async (req, res) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
        select: { id: true, email: true, name: true, createdAt: true },
      });

      if (!user) return res.status(404).json({ error: "User not found" });
      return res.status(200).json({ user });
    } catch (error) {
      console.error("Profile error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/dashboard", requireAuth, async (req, res) => {
    try {
      const user = await prisma.user.findUnique({
        where: { id: req.user.id },
        select: { email: true, name: true },
      });

      if (!user) return res.status(404).json({ error: "User not found" });

      const displayName = user.name && user.name.trim() ? user.name : user.email;
      return res.status(200).json({ message: `Welcome, ${displayName}!` });
    } catch (error) {
      console.error("Dashboard error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  return app;
}

if (require.main === module) {
  const app = createApp();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}

module.exports = { createApp };
