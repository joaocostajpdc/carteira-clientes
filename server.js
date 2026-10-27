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
  ssl: { rejectUnauthorized: true }
});

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "60mb" }));
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
    const { rows } = await pool.query("SELECT data, updated_at::text AS rev FROM app_state WHERE id = 1");
    if (rows.length) res.setHeader("X-State-Rev", rows[0].rev);
    res.setHeader("Cache-Control", "no-store");
    res.json(rows.length ? rows[0].data : {});
  } catch (err) {
    console.error("GET /api/state failed", err);
    res.status(500).json({ error: "db_error" });
  }
});

/* ---------- PDFs guardados à parte (2026-10-22) ----------
   Os PDFs originais das encomendas/orçamentos iam dentro do estado e cada
   gravação enviava tudo (passou os 5 MB e as gravações começaram a falhar).
   Agora cada PDF vai para a tabela app_files e no estado fica só "file:<id>". */
async function extractFiles(data, client) {
  const replaced = {};
  for (const kind of ["orders", "quotes"]) {
    const list = Array.isArray(data[kind]) ? data[kind] : [];
    for (const rec of list) {
      if (rec && typeof rec.pdfData === "string" && rec.pdfData.startsWith("data:")) {
        const id = "pdf_" + String(rec.id || crypto.randomBytes(6).toString("hex")).replace(/[^\w-]/g, "");
        await client.query(
          "INSERT INTO app_files (id, data, created_at) VALUES ($1, $2, now()) ON CONFLICT (id) DO UPDATE SET data = $2",
          [id, rec.pdfData]
        );
        rec.pdfData = "file:" + id;
        replaced[rec.id] = rec.pdfData;
      }
    }
  }
  return replaced;
}

app.get("/api/files/:id", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT data FROM app_files WHERE id = $1", [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "not_found" });
    const m = /^data:([^;]+);base64,(.*)$/s.exec(rows[0].data);
    if (!m) return res.status(500).json({ error: "bad_file" });
    res.setHeader("Content-Type", m[1]);
    res.setHeader("Cache-Control", "private, max-age=86400");
    res.send(Buffer.from(m[2], "base64"));
  } catch (err) {
    console.error("GET /api/files failed", err);
    res.status(500).json({ error: "db_error" });
  }
});

app.put("/api/state", requireAuth, async (req, res) => {
  const data = req.body;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return res.status(400).json({ error: "invalid_body" });
  }
  // Proteção contra páginas desatualizadas (2026-10-24): uma página aberta
  // há muito tempo voltava a gravar o estado antigo por cima das alterações
  // feitas noutro aparelho (ex.: visitas apagadas que reapareciam). Agora cada
  // gravação tem de indicar a versão que a página carregou; se entretanto
  // alguém gravou, recusa (409) e a página vai buscar a versão nova.
  const rev = req.get("X-State-Rev");
  if (!rev) return res.status(409).json({ error: "stale" });
  let files = {};
  try {
    files = await extractFiles(data, pool);
    const r = await pool.query(
      "UPDATE app_state SET data = $1, updated_at = now() WHERE id = 1 AND updated_at::text = $2 RETURNING updated_at::text AS rev",
      [JSON.stringify(data), rev]
    );
    if (!r.rows.length) return res.status(409).json({ error: "stale" });
    res.setHeader("X-State-Rev", r.rows[0].rev);
    res.json({ ok: true, files, rev: r.rows[0].rev });
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
  await pool.query(
    "CREATE TABLE IF NOT EXISTS app_files (" +
    "id TEXT PRIMARY KEY, " +
    "data TEXT NOT NULL, " +
    "created_at TIMESTAMPTZ NOT NULL DEFAULT now()" +
    ")"
  );
  // Migração: tira os PDFs que ainda estiverem dentro do estado guardado.
  const cur = await pool.query("SELECT data FROM app_state WHERE id = 1");
  if (cur.rows.length) {
    const st = cur.rows[0].data;
    const moved = await extractFiles(st, pool);
    if (Object.keys(moved).length) {
      await pool.query("UPDATE app_state SET data = $1 WHERE id = 1", [JSON.stringify(st)]);
      console.log("PDFs movidos para app_files:", Object.keys(moved).length);
    }
  }
  // Prospeção de mercado (2026-10-27): carrega uma única vez a lista do Excel
  // "Prosperação mercado JPDC" (Portugal e Espanha) para a nova página
  // Prospeção. Se já houver empresas em prospeção, não mexe em nada.
  try {
    const leads = require("./seed_leads.json");
    const r = await pool.query(
      "UPDATE app_state SET data = jsonb_set(data, '{leads}', $1::jsonb), updated_at = now() " +
      "WHERE id = 1 AND (NOT (data ? 'leads') OR jsonb_array_length(data->'leads') = 0) RETURNING id",
      [JSON.stringify(leads)]
    );
    if (r.rows.length) console.log("Prospeção: " + leads.length + " empresas carregadas.");
  } catch (err) {
    console.error("Prospeção: não foi possível carregar a lista", err);
  }
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

// Start listening even if the database is unreachable, so the page still loads
// and the browser can fall back to its local copy of the data (the API
// returns 500 "db_error" until the database is available again).
ensureSchema()
  .then(() => console.log("Database ready."))
  .catch((err) => {
    console.error("Failed to initialize database", err);
  })
  .finally(() => {
    app.listen(PORT, () => console.log("Listening on port " + PORT));
  });
