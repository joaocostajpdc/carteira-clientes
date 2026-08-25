"use strict";

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const APP_PASSWORD = process.env.APP_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 180; // 180 days

if (!APP_PASSWORD) {
  console.warn("WARNING: APP_PASSWORD is not set — login will always fail until it is configured.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());

/* ---------- session helpers ---------- */
function makeToken() {
  const exp = String(Date.now() + SESSION_MAX_AGE_MS);
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(exp).digest("hex");
  return exp + "." + sig;
}
function verifyToken(token) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [exp, sig] = parts;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(exp).digest("hex");
  const sigBuf = Buffer.from(sig, "hex");
  const expBuf = Buffer.from(expected, "hex");
  if (sigBuf.length !== expBuf.length) return false;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return false;
  const expNum = Number(exp);
  if (!expNum || Date.now() > expNum) return false;
  return true;
}
function requireAuth(req, res, next) {
  if (!verifyToken(req.cookies && req.cookies.session)) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

/* ---------- routes ---------- */
app.get("/healthz", (req, res) => res.status(200).send("ok"));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/api/login", (req, res) => {
  const password = (req.body && req.body.password) || "";
  if (!APP_PASSWORD || password !== APP_PASSWORD) {
    return res.status(401).json({ error: "invalid" });
  }
  const token = makeToken();
  res.cookie("session", token, {
    httpOnly: true,
    secure: req.secure,
    sameSite: "lax",
    maxAge: SESSION_MAX_AGE_MS,
    path: "/"
  });
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("session", { path: "/" });
  res.json({ ok: true });
});

app.get("/api/state", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT data FROM app_state WHERE id = 1");
    res.json(rows.length ? rows[0].data : {});
  } catch (err) {
    console.error("GET /api/state failed", err);
    res.status(500).json({ error: "db_error" });
  }
});

app.put("/api/state", requireAuth, async (req, res) => {
  const data = req.body;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return res.status(400).json({ error: "invalid_body" });
  }
  try {
    await pool.query(
      "INSERT INTO app_state (id, data, updated_at) VALUES (1, $1, now()) " +
      "ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()",
      [JSON.stringify(data)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("PUT /api/state failed", err);
    res.status(500).json({ error: "db_error" });
  }
});

/* ---------- boot ---------- */
async function ensureSchema() {
  await pool.query(
    "CREATE TABLE IF NOT EXISTS app_state (" +
    "id INTEGER PRIMARY KEY, " +
    "data JSONB NOT NULL, " +
    "updated_at TIMESTAMPTZ NOT NULL DEFAULT now()" +
    ")"
  );
  const { rows } = await pool.query("SELECT id FROM app_state WHERE id = 1");
  if (rows.length === 0) {
    const seed = require("./seed_data.json");
    await pool.query(
      "INSERT INTO app_state (id, data, updated_at) VALUES (1, $1, now())",
      [JSON.stringify(seed)]
    );
    console.log("Seeded initial data into app_state.");
  }
}

ensureSchema()
  .then(() => {
    app.listen(PORT, () => console.log("Listening on port " + PORT));
  })
  .catch((err) => {
    console.error("Failed to initialize database", err);
    process.exit(1);
  });
