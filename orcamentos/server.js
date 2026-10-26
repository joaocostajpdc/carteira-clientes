"use strict";
/* Programa de orçamentação — Minho Ferragens (chapas quinadas e painéis) */
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const APP_PASSWORD = process.env.APP_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 180; // 180 dias

if (!APP_PASSWORD) console.warn("WARNING: APP_PASSWORD is not set — login will always fail until it is configured.");

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: true } });
const app = express();
app.set("trust proxy", 1);
app.use(cookieParser());

/* ---------- sessão ---------- */
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
  const a = Buffer.from(sig, "hex"), b = Buffer.from(expected, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  const n = Number(exp);
  return !!n && Date.now() <= n;
}
function requireAuth(req, res, next) {
  if (!verifyToken(req.cookies && req.cookies.session)) return res.status(401).json({ error: "unauthorized" });
  next();
}
const json = express.json({ limit: "2mb" });
const ID_RE = /^[A-Za-z0-9_\-.~:@+]{1,120}$/;

/* tentativas de login: máx. 10 por 15 min por IP */
const attempts = new Map();
function rateLimited(ip) {
  const now = Date.now(), win = 15 * 60 * 1000;
  const a = (attempts.get(ip) || []).filter(t => now - t < win);
  attempts.set(ip, a);
  return a.length >= 10;
}

/* ---------- rotas ---------- */
app.get("/healthz", (req, res) => res.send("ok"));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.post("/api/login", json, (req, res) => {
  const ip = req.ip || "?";
  if (rateLimited(ip)) return res.status(429).json({ error: "too_many" });
  const pw = (req.body && req.body.password) || "";
  const ok = APP_PASSWORD && pw.length === APP_PASSWORD.length &&
    crypto.timingSafeEqual(Buffer.from(pw), Buffer.from(APP_PASSWORD));
  if (!ok) { attempts.get(ip).push(Date.now()); return res.status(401).json({ error: "invalid" }); }
  res.cookie("session", makeToken(), { httpOnly: true, secure: req.secure, sameSite: "lax", maxAge: SESSION_MAX_AGE_MS, path: "/" });
  res.json({ ok: true });
});
app.post("/api/logout", (req, res) => { res.clearCookie("session", { path: "/" }); res.json({ ok: true }); });

app.get("/api/bootstrap", requireAuth, async (req, res) => {
  try {
    const cfg = await pool.query("SELECT key, data FROM orc_config");
    const q = await pool.query("SELECT id, data FROM orc_quotes");
    const out = { precos: null, empresa: null, orcamentos: q.rows.map(r => ({ ...r.data, id: r.id })) };
    cfg.rows.forEach(r => { out[r.key] = r.data; });
    res.json(out);
  } catch (e) { console.error(e); res.status(500).json({ error: "db_error" }); }
});
app.get("/api/orcamentos", requireAuth, async (req, res) => {
  try { const q = await pool.query("SELECT id, data FROM orc_quotes"); res.json(q.rows.map(r => ({ ...r.data, id: r.id }))); }
  catch (e) { console.error(e); res.status(500).json({ error: "db_error" }); }
});
app.put("/api/orcamentos/:id", requireAuth, json, async (req, res) => {
  const id = req.params.id, d = req.body;
  if (!ID_RE.test(id) || !d || typeof d !== "object" || Array.isArray(d)) return res.status(400).json({ error: "invalid" });
  delete d.id;
  try {
    await pool.query("INSERT INTO orc_quotes (id, data, updated_at) VALUES ($1,$2,now()) ON CONFLICT (id) DO UPDATE SET data=$2, updated_at=now()", [id, JSON.stringify(d)]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "db_error" }); }
});
app.patch("/api/orcamentos/:id", requireAuth, json, async (req, res) => {
  const id = req.params.id, d = req.body;
  if (!ID_RE.test(id) || !d || typeof d !== "object" || Array.isArray(d)) return res.status(400).json({ error: "invalid" });
  delete d.id;
  try {
    const r = await pool.query("UPDATE orc_quotes SET data = data || $2::jsonb, updated_at=now() WHERE id=$1", [id, JSON.stringify(d)]);
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "db_error" }); }
});
app.delete("/api/orcamentos/:id", requireAuth, async (req, res) => {
  try { await pool.query("DELETE FROM orc_quotes WHERE id=$1", [req.params.id]); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: "db_error" }); }
});
app.put("/api/config/:key", requireAuth, json, async (req, res) => {
  const key = req.params.key, d = req.body;
  if (!["precos", "empresa"].includes(key) || !d || typeof d !== "object") return res.status(400).json({ error: "invalid" });
  try {
    await pool.query("INSERT INTO orc_config (key, data, updated_at) VALUES ($1,$2,now()) ON CONFLICT (key) DO UPDATE SET data=$2, updated_at=now()", [key, JSON.stringify(d)]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "db_error" }); }
});

/* desenhos do cliente e logótipo */
const MIMES = ["image/jpeg", "image/png"];
app.post("/api/files", requireAuth, express.raw({ type: MIMES, limit: "15mb" }), async (req, res) => {
  const mime = (req.headers["content-type"] || "").split(";")[0].trim();
  if (!MIMES.includes(mime) || !Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: "invalid" });
  const id = crypto.randomBytes(12).toString("hex");
  try { await pool.query("INSERT INTO orc_files (id, mime, bytes) VALUES ($1,$2,$3)", [id, mime, req.body]); res.json({ id, url: "/files/" + id }); }
  catch (e) { console.error(e); res.status(500).json({ error: "db_error" }); }
});
app.get("/files/:id", requireAuth, async (req, res) => {
  if (!/^[a-f0-9]{24}$/.test(req.params.id)) return res.status(404).end();
  try {
    const r = await pool.query("SELECT mime, bytes FROM orc_files WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).end();
    res.set("Content-Type", r.rows[0].mime).set("Cache-Control", "private, max-age=31536000, immutable").send(r.rows[0].bytes);
  } catch (e) { console.error(e); res.status(500).end(); }
});

/* ---------- arranque ---------- */
async function ensureSchema() {
  await pool.query("CREATE TABLE IF NOT EXISTS orc_quotes (id TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())");
  await pool.query("CREATE TABLE IF NOT EXISTS orc_config (key TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())");
  await pool.query("CREATE TABLE IF NOT EXISTS orc_files (id TEXT PRIMARY KEY, mime TEXT NOT NULL, bytes BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())");
  const { rows } = await pool.query("SELECT count(*)::int n FROM orc_config");
  if (rows[0].n === 0) {
    const seed = require("./seed_data.json");
    await pool.query("INSERT INTO orc_config (key, data) VALUES ('precos',$1),('empresa',$2) ON CONFLICT DO NOTHING", [JSON.stringify(seed.precos), JSON.stringify(seed.empresa)]);
    for (const q of seed.orcamentos) {
      const { id, ...d } = q;
      await pool.query("INSERT INTO orc_quotes (id, data) VALUES ($1,$2) ON CONFLICT DO NOTHING", [id, JSON.stringify(d)]);
    }
    console.log("Seeded " + seed.orcamentos.length + " orçamentos.");
  }
}
ensureSchema().then(() => console.log("Database ready.")).catch(e => console.error("DB init failed", e))
  .finally(() => app.listen(PORT, () => console.log("Listening on port " + PORT)));
