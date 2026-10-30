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

// Diagnóstico (2026-10-28): regista o resultado de cada gravação para se
// perceber porque é que uma falha (antes só os erros da base de dados ficavam
// nos registos).
app.use("/api/state", (req, res, next) => {
  if (req.method !== "PUT") return next();
  const t0 = Date.now();
  res.on("finish", () => {
    console.log("[gravar] PUT /api/state -> " + res.statusCode + " (" + (req.get("content-length") || "?") + " bytes, rev=" + (req.get("X-State-Rev") || "vazio") + ", " + (Date.now() - t0) + " ms)");
  });
  next();
});

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
// Limites oficiais dos distritos e concelhos (CAOP, simplificados) para o
// mapa dos clientes — ficheiro já comprimido (2026-10-30).
const PT_MAPA_GZ = path.join(__dirname, "pt_mapa.json.gz");
app.get("/pt_mapa.json", (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Encoding", "gzip");
  res.setHeader("Cache-Control", "public, max-age=604800");
  res.sendFile(PT_MAPA_GZ);
});

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

// Erros vistos na página (falhas a gravar, erros de JavaScript) — ficam nos
// registos do servidor para se poder diagnosticar à distância.
app.post("/api/client-log", express.json({ limit: "20kb" }), (req, res) => {
  const b = req.body || {};
  const msg = String(b.msg || "").slice(0, 2000);
  const ua = String(req.get("user-agent") || "").slice(0, 160);
  const auth = verifyToken(req.cookies && req.cookies.session) ? "sessão ok" : "sem sessão";
  console.warn("[página] " + msg + " | " + auth + " | " + ua);
  res.json({ ok: true });
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
  if (!rev) { console.warn("[gravar] recusado: página sem versão (X-State-Rev vazio)"); return res.status(409).json({ error: "stale" }); }
  let files = {};
  try {
    files = await extractFiles(data, pool);
    const r = await pool.query(
      "UPDATE app_state SET data = $1, updated_at = now() WHERE id = 1 AND updated_at::text = $2 RETURNING updated_at::text AS rev",
      [JSON.stringify(data), rev]
    );
    if (!r.rows.length) {
      const cur = await pool.query("SELECT updated_at::text AS rev FROM app_state WHERE id = 1");
      console.warn("[gravar] recusado: versão da página " + rev + " ≠ versão atual " + (cur.rows[0] && cur.rows[0].rev));
      return res.status(409).json({ error: "stale" });
    }
    res.setHeader("X-State-Rev", r.rows[0].rev);
    res.json({ ok: true, files, rev: r.rows[0].rev });
  } catch (err) {
    console.error("PUT /api/state failed", err);
    res.status(500).json({ error: "db_error" });
  }
});

/* ---------- Localização para o mapa (2026-10-27) ----------
   O mapa da Prospeção precisa das coordenadas de cada empresa. Procurar no
   browser falhava (o OpenStreetMap recusa pedidos sem identificação e com
   muitos seguidos), e as empresas ficavam todas no centro do distrito. Agora
   é o servidor que procura, com identificação própria e 1 pedido por
   segundo, e guarda o resultado numa tabela à parte (geo_cache), por isso
   não mexe nos dados da carteira nem atrapalha quem está a trabalhar.
   Cada pedido traz uma lista de tentativas por ordem (localidade completa,
   só o concelho, o distrito); a primeira que der resultado fica. */
const GEO_UA = "CarteiraClientes-MinhoFerragens/1.0 (geral@minhoferragens.pt)";
let geoBusy = false;
async function nominatim(q, cc) {
  const url = "https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1&addressdetails=0&accept-language=pt" +
    (cc ? "&countrycodes=" + encodeURIComponent(cc) : "") + "&q=" + encodeURIComponent(q);
  const r = await fetch(url, { headers: { "User-Agent": GEO_UA, "Accept": "application/json", "Referer": "https://carteira-clientes.onrender.com/" } });
  if (r.status === 429 || r.status === 403) throw new Error("geo_blocked_" + r.status);
  if (!r.ok) return null;
  const j = await r.json();
  return Array.isArray(j) && j[0] ? { lat: parseFloat(j[0].lat), lng: parseFloat(j[0].lon) } : null;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function runGeoQueue() {
  if (geoBusy) return;
  geoBusy = true;
  try {
    for (;;) {
      const { rows } = await pool.query(
        "SELECT key, tries, cc FROM geo_cache WHERE status = 'pendente' ORDER BY created_at LIMIT 20"
      );
      if (!rows.length) break;
      for (const row of rows) {
        const tries = Array.isArray(row.tries) ? row.tries : [];
        let found = null, prec = "nao";
        try {
          for (let i = 0; i < tries.length; i++) {
            const pos = await nominatim(tries[i], row.cc);
            await sleep(1100);
            if (pos) { found = pos; prec = i === tries.length - 1 && tries.length > 1 ? "distrito" : "local"; break; }
          }
        } catch (err) {
          console.warn("Mapa: o OpenStreetMap pediu para abrandar (" + err.message + "); volto a tentar daqui a 2 min.");
          await sleep(120000);
          continue;
        }
        await pool.query(
          "UPDATE geo_cache SET status = 'feito', lat = $2, lng = $3, prec = $4, updated_at = now() WHERE key = $1",
          [row.key, found ? found.lat : null, found ? found.lng : null, prec]
        );
      }
    }
  } catch (err) {
    console.error("Mapa: erro na fila de localização", err);
  } finally {
    geoBusy = false;
  }
}

// A página envia as moradas que precisa de ver no mapa e recebe as que já
// estão localizadas; as novas ficam na fila.
app.post("/api/geo", requireAuth, async (req, res) => {
  try {
    const items = Array.isArray(req.body && req.body.items) ? req.body.items.slice(0, 2000) : [];
    const keys = [];
    for (const it of items) {
      if (!it || typeof it.key !== "string" || !it.key || it.key.length > 400) continue;
      const tries = Array.isArray(it.tries) ? it.tries.filter((t) => typeof t === "string" && t.trim()).slice(0, 5) : [];
      if (!tries.length) continue;
      keys.push(it.key);
      await pool.query(
        "INSERT INTO geo_cache (key, tries, cc, status) VALUES ($1, $2, $3, 'pendente') ON CONFLICT (key) DO NOTHING",
        [it.key, JSON.stringify(tries), typeof it.cc === "string" ? it.cc.slice(0, 5) : null]
      );
    }
    const { rows } = await pool.query(
      "SELECT key, lat, lng, prec, status FROM geo_cache WHERE key = ANY($1::text[])", [keys]
    );
    const out = {};
    let pendentes = 0;
    for (const r of rows) {
      if (r.status === "pendente") { pendentes++; continue; }
      out[r.key] = r.lat === null ? null : { lat: r.lat, lng: r.lng, prec: r.prec };
    }
    res.setHeader("Cache-Control", "no-store");
    res.json({ found: out, pendentes });
    if (pendentes) runGeoQueue();
  } catch (err) {
    console.error("POST /api/geo failed", err);
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
  await pool.query(
    "CREATE TABLE IF NOT EXISTS geo_cache (" +
    "key TEXT PRIMARY KEY, tries JSONB NOT NULL, cc TEXT, status TEXT NOT NULL DEFAULT 'pendente', " +
    "lat DOUBLE PRECISION, lng DOUBLE PRECISION, prec TEXT, " +
    "created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"
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
  .then(() => { console.log("Database ready."); runGeoQueue(); })
  .catch((err) => {
    console.error("Failed to initialize database", err);
  })
  .finally(() => {
    app.listen(PORT, () => console.log("Listening on port " + PORT));
  });
