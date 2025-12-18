import os
import json
import hmac
import hashlib
from urllib.parse import parse_qsl
from typing import Dict, Any, List, Optional

import psycopg
from psycopg.rows import dict_row

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse


# =========================
# Env
# =========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
APP_TITLE = os.getenv("APP_TITLE", "Robinhood_alert Dashboard")

if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN env var")
if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL env var")

app = FastAPI(title=APP_TITLE)


# =========================
# Telegram Mini App auth
# =========================
def verify_telegram_init_data(init_data: str) -> Dict[str, Any]:
    """
    Verifies Telegram WebApp initData (HMAC check).
    """
    if not init_data or "hash=" not in init_data:
        raise HTTPException(status_code=401, detail="Missing initData")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", "")

    data_check_string = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs.keys()))

    # ✅ Telegram WebApp secret key
    secret_key = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise HTTPException(status_code=401, detail="Bad initData signature")

    user_raw = pairs.get("user")
    if not user_raw:
        raise HTTPException(status_code=401, detail="No user in initData")

    user = json.loads(user_raw)

    return {
        "telegram_user": user,
        "telegram_user_id": int(user.get("id")),
        "username": user.get("username"),
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
    }


def get_init_data_from_request(req: Request) -> str:
    # Header recomendado (lo mandamos desde JS)
    init_data = req.headers.get("X-Telegram-Init-Data", "").strip()
    if init_data:
        return init_data

    # Fallback: query param
    q = req.query_params.get("initData", "")
    return (q or "").strip()


def require_user(req: Request) -> Dict[str, Any]:
    init_data = get_init_data_from_request(req)
    return verify_telegram_init_data(init_data)


# =========================
# DB helpers (psycopg v3)
# =========================
def db():
    # autocommit True para simplicidad
    return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row)


def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    telegram_user_id BIGINT PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    weekly_budget NUMERIC DEFAULT 0,
                    dip_budget NUMERIC DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    updated_at TIMESTAMPTZ DEFAULT now()
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    telegram_user_id BIGINT NOT NULL,
                    ticker TEXT NOT NULL,
                    drop_pct NUMERIC NOT NULL DEFAULT 0,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    PRIMARY KEY (telegram_user_id, ticker)
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS dca_rules (
                    telegram_user_id BIGINT NOT NULL,
                    ticker TEXT NOT NULL,
                    levels_json TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (telegram_user_id, ticker)
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS monday_plan (
                    telegram_user_id BIGINT NOT NULL,
                    ticker TEXT NOT NULL,
                    amount NUMERIC NOT NULL DEFAULT 0,
                    PRIMARY KEY (telegram_user_id, ticker)
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    telegram_user_id BIGINT PRIMARY KEY,
                    priority_json TEXT NOT NULL DEFAULT '[]'
                );
            """)


@app.on_event("startup")
def on_startup():
    init_db()


def upsert_user(u: Dict[str, Any]):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (telegram_user_id, username, first_name, last_name)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (telegram_user_id) DO UPDATE SET
                    username = EXCLUDED.username,
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    updated_at = now();
            """, (u["telegram_user_id"], u.get("username"), u.get("first_name"), u.get("last_name")))


# =========================
# UI (Dashboard)
# =========================
@app.get("/", response_class=HTMLResponse)
def home():
    # NO f-strings aquí para evitar problemas con ${} del JS
    title = APP_TITLE

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{title}</title>
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    :root {{
      --bg: #0b0f14;
      --card: #121826;
      --muted: #9aa4b2;
      --text: #e6edf3;
      --line: rgba(255,255,255,.08);
      --btn: #1f6feb;
      --btn2: #2ea043;
      --danger: #f85149;
      --chip: rgba(255,255,255,.06);
    }}
    body {{
      margin: 0; background: var(--bg); color: var(--text);
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Arial;
    }}
    .wrap {{ max-width: 860px; margin: 0 auto; padding: 16px; }}
    .top {{
      display:flex; justify-content:space-between; align-items:center;
      gap:12px; margin-bottom: 12px;
    }}
    .title {{ font-size: 20px; font-weight: 700; }}
    .sub {{ font-size: 12px; color: var(--muted); }}
    .tabs {{
      display:flex; gap:8px; flex-wrap:wrap; margin: 12px 0 16px;
    }}
    .tab {{
      background: var(--chip); border:1px solid var(--line);
      padding: 8px 10px; border-radius: 10px; font-size: 13px;
      cursor:pointer; user-select:none;
    }}
    .tab.active {{ outline: 2px solid rgba(31,111,235,.45); }}
    .grid {{
      display:grid; grid-template-columns: 1fr; gap: 12px;
    }}
    @media (min-width: 880px) {{
      .grid {{ grid-template-columns: 1fr 1fr; }}
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px;
    }}
    .h {{ font-weight:700; margin-bottom:8px; }}
    .row {{ display:flex; gap:10px; margin: 10px 0; flex-wrap:wrap; }}
    .field {{ flex:1; min-width: 140px; }}
    label {{ display:block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }}
    input {{
      width: 100%; box-sizing:border-box;
      border-radius: 12px;
      border:1px solid var(--line);
      background: rgba(255,255,255,.03);
      color: var(--text);
      padding: 10px 12px;
      outline: none;
    }}
    .btnrow {{ display:flex; gap:10px; flex-wrap:wrap; }}
    button {{
      border:0; padding: 10px 12px; border-radius: 12px;
      cursor:pointer; font-weight:700;
    }}
    .btn {{ background: var(--btn); color: white; }}
    .btn2 {{ background: var(--btn2); color: white; }}
    .danger {{ background: var(--danger); color: white; }}
    .ghost {{
      background: transparent; color: var(--text);
      border:1px solid var(--line);
    }}
    .list {{
      margin-top: 10px; border-top: 1px solid var(--line); padding-top: 10px;
      font-size: 13px; color: var(--muted);
      max-height: 160px; overflow:auto;
    }}
    .pill {{
      display:inline-block; padding: 6px 10px; border-radius: 999px;
      border:1px solid var(--line); background: var(--chip);
      margin: 4px 6px 0 0; color: var(--text); font-size: 12px;
    }}
    .ok {{ color: #7ee787; }}
    .warn {{ color: #f0c36c; }}
  </style>
</head>

<body>
  <div class="wrap">
    <div class="top">
      <div>
        <div class="title">{title}</div>
        <div class="sub" id="meSub">Cargando usuario…</div>
      </div>
      <div class="btnrow">
        <button class="ghost" id="btnReload">Actualizar</button>
      </div>
    </div>

    <div class="tabs" id="tabs">
      <div class="tab active" data-tab="resumen">Resumen</div>
      <div class="tab" data-tab="presupuesto">Presupuesto</div>
      <div class="tab" data-tab="alertas">Alertas</div>
      <div class="tab" data-tab="dca">DCA</div>
      <div class="tab" data-tab="lunes">Plan Lunes</div>
      <div class="tab" data-tab="prioridad">Prioridad</div>
    </div>

    <div class="grid">
      <div class="card" data-pane="resumen">
        <div class="h">✅ Estado</div>
        <div class="sub">Este servicio corre en Render. Tu bot usa la misma DB.</div>
        <div class="row">
          <span class="pill" id="pillDb">DB: …</span>
          <span class="pill" id="pillAuth">Auth: …</span>
        </div>
        <div class="btnrow">
          <button class="btn2" id="btnQuick">⚡ Aplicar configuración rápida</button>
          <button class="ghost" id="btnOpenBot">Abrir bot</button>
        </div>
        <div class="list" id="logBox"></div>
      </div>

      <div class="card" data-pane="presupuesto" style="display:none;">
        <div class="h">💰 Presupuesto</div>
        <div class="row">
          <div class="field">
            <label>Semanal (para compras lunes)</label>
            <input id="weekly_budget" type="number" placeholder="70" />
          </div>
          <div class="field">
            <label>Dips (para caídas fuertes)</label>
            <input id="dip_budget" type="number" placeholder="40" />
          </div>
        </div>
        <div class="btnrow">
          <button class="btn" id="btnSaveBudget">Guardar</button>
          <button class="ghost" id="btnLoadBudget">Cargar</button>
        </div>
      </div>

      <div class="card" data-pane="alertas" style="display:none;">
        <div class="h">📌 Alertas por caída</div>
        <div class="sub">Ej: “NVDA caída ≥ 15%”, “QQQ caída ≥ 10%”.</div>
        <div class="row">
          <div class="field">
            <label>Ticker</label>
            <input id="a_ticker" placeholder="NVDA" />
          </div>
          <div class="field">
            <label>% caída</label>
            <input id="a_drop" type="number" placeholder="15" />
          </div>
        </div>
        <div class="btnrow">
          <button class="btn" id="btnSaveAlert">Guardar alerta</button>
          <button class="danger" id="btnDelAlert">Eliminar</button>
          <button class="ghost" id="btnLoadAlerts">Ver lista</button>
        </div>
        <div class="list" id="alertsList"></div>
      </div>

      <div class="card" data-pane="dca" style="display:none;">
        <div class="h">🧠 DCA Inteligente</div>
        <div class="sub">Formato niveles: <b>10:15 25:25 35:40</b> (caída:monto).</div>
        <div class="row">
          <div class="field">
            <label>Ticker</label>
            <input id="d_ticker" placeholder="NVDA" />
          </div>
          <div class="field">
            <label>Niveles</label>
            <input id="d_levels" placeholder="15:15 25:25 35:40" />
          </div>
        </div>
        <div class="btnrow">
          <button class="btn" id="btnSaveDca">Guardar DCA</button>
          <button class="danger" id="btnDelDca">Eliminar</button>
          <button class="ghost" id="btnLoadDca">Ver DCA</button>
        </div>
        <div class="list" id="dcaList"></div>
      </div>

      <div class="card" data-pane="lunes" style="display:none;">
        <div class="h">🏆 Plan fijo Lunes</div>
        <div class="sub">Ej: QQQ 30, SCHD 20, JEPQ 20 (total 70).</div>
        <div class="row">
          <div class="field">
            <label>Ticker</label>
            <input id="m_ticker" placeholder="QQQ" />
          </div>
          <div class="field">
            <label>Monto</label>
            <input id="m_amount" type="number" placeholder="30" />
          </div>
        </div>
        <div class="btnrow">
          <button class="btn" id="btnSaveMonday">Guardar item</button>
          <button class="danger" id="btnDelMonday">Eliminar</button>
          <button class="ghost" id="btnLoadMonday">Ver plan</button>
        </div>
        <div class="list" id="mondayList"></div>
      </div>

      <div class="card" data-pane="prioridad" style="display:none;">
        <div class="h">🥇 Prioridad</div>
        <div class="sub">Orden de preferencia para usar el presupuesto de dips.</div>
        <div class="row">
          <div class="field">
            <label>Orden (separado por espacios)</label>
            <input id="p_order" placeholder="NVDA QQQ JEPQ SCHD" />
          </div>
        </div>
        <div class="btnrow">
          <button class="btn" id="btnSavePriority">Guardar prioridad</button>
          <button class="ghost" id="btnLoadPriority">Ver prioridad</button>
        </div>
        <div class="list" id="priorityBox"></div>
      </div>
    </div>
  </div>

<script>
  const tg = window.Telegram?.WebApp;
  const initData = tg?.initData || "";

  function log(msg) {{
    const box = document.getElementById("logBox");
    const t = new Date().toLocaleTimeString();
    box.innerHTML = `<div>• [${{t}}] ${{msg}}</div>` + box.innerHTML;
  }}

  async function api(path, options={{}}) {{
    const headers = options.headers || {{}};
    headers["X-Telegram-Init-Data"] = initData;
    headers["Content-Type"] = "application/json";
    const res = await fetch(path, {{...options, headers}});
    let data = null;
    try {{ data = await res.json(); }} catch (e) {{}}
    if (!res.ok) {{
      const msg = (data && (data.detail || data.error)) ? (data.detail || data.error) : `HTTP ${{res.status}}`;
      throw new Error(msg);
    }}
    return data;
  }}

  function setActiveTab(tabName) {{
    document.querySelectorAll(".tab").forEach(t => {{
      t.classList.toggle("active", t.dataset.tab === tabName);
    }});
    document.querySelectorAll("[data-pane]").forEach(p => {{
      p.style.display = (p.dataset.pane === tabName) ? "" : "none";
    }});
  }}

  document.getElementById("tabs").addEventListener("click", (e) => {{
    const tab = e.target.closest(".tab");
    if (!tab) return;
    setActiveTab(tab.dataset.tab);
  }});

  document.getElementById("btnReload").onclick = () => initAll();

  document.getElementById("btnOpenBot").onclick = () => {{
    tg?.openTelegramLink?.("https://t.me/robin_hood_alet_bot");
  }};

  async function initAll() {{
    if (!tg) {{
      document.getElementById("meSub").innerText = "⚠️ Abre esto dentro de Telegram (Mini App).";
      document.getElementById("pillAuth").innerText = "Auth: OFF";
      document.getElementById("pillAuth").className = "pill warn";
      return;
    }}
    tg.ready();
    try {{
      const me = await api("/api/me");
      document.getElementById("meSub").innerText = `👤 ${me.first_name || ""} ${me.last_name || ""} (@${me.username || "sin_user"}) • ID ${me.telegram_user_id}`;
      document.getElementById("pillAuth").innerText = "Auth: OK";
      document.getElementById("pillAuth").className = "pill ok";
      document.getElementById("pillDb").innerText = "DB: OK";
      document.getElementById("pillDb").className = "pill ok";
      log("Mini App conectada ✅");
    }} catch (err) {{
      document.getElementById("meSub").innerText = "❌ Error auth: " + err.message;
      document.getElementById("pillAuth").innerText = "Auth: FAIL";
      document.getElementById("pillAuth").className = "pill warn";
      log("Error: " + err.message);
    }}
  }}

  // ===== Presupuesto =====
  document.getElementById("btnSaveBudget").onclick = async () => {{
    const weekly = Number(document.getElementById("weekly_budget").value || 0);
    const dip = Number(document.getElementById("dip_budget").value || 0);
    const r = await api("/api/budget", {{
      method: "POST",
      body: JSON.stringify({{ weekly_budget: weekly, dip_budget: dip }})
    }});
    log("Presupuesto guardado ✅");
  }};

  document.getElementById("btnLoadBudget").onclick = async () => {{
    const r = await api("/api/budget");
    document.getElementById("weekly_budget").value = r.weekly_budget;
    document.getElementById("dip_budget").value = r.dip_budget;
    log("Presupuesto cargado ✅");
  }};

  // ===== Alertas =====
  function renderAlerts(items) {{
    const box = document.getElementById("alertsList");
    if (!items.length) {{
      box.innerHTML = "<div>Sin alertas todavía.</div>";
      return;
    }}
    box.innerHTML = items.map(a => `<div>📌 <b>${a.ticker}</b> — caída ≥ <b>${a.drop_pct}%</b> ${a.enabled ? "" : "(off)"}</div>`).join("");
  }}

  document.getElementById("btnSaveAlert").onclick = async () => {{
    const ticker = (document.getElementById("a_ticker").value || "").trim().toUpperCase();
    const drop = Number(document.getElementById("a_drop").value || 0);
    await api("/api/alerts", {{
      method: "POST",
      body: JSON.stringify({{ ticker, drop_pct: drop, enabled: true }})
    }});
    log(`Alerta guardada: ${ticker} ≥ ${drop}%`);
    renderAlerts((await api("/api/alerts")).items);
  }};

  document.getElementById("btnDelAlert").onclick = async () => {{
    const ticker = (document.getElementById("a_ticker").value || "").trim().toUpperCase();
    await api("/api/alerts/" + encodeURIComponent(ticker), {{ method: "DELETE" }});
    log(`Alerta eliminada: ${ticker}`);
    renderAlerts((await api("/api/alerts")).items);
  }};

  document.getElementById("btnLoadAlerts").onclick = async () => {{
    renderAlerts((await api("/api/alerts")).items);
  }};

  // ===== DCA =====
  function renderDca(items) {{
    const box = document.getElementById("dcaList");
    if (!items.length) {{
      box.innerHTML = "<div>Sin DCA todavía.</div>";
      return;
    }}
    box.innerHTML = items.map(d => `<div>🧠 <b>${d.ticker}</b> — ${d.levels.join(" ")}</div>`).join("");
  }}

  document.getElementById("btnSaveDca").onclick = async () => {{
    const ticker = (document.getElementById("d_ticker").value || "").trim().toUpperCase();
    const levels = (document.getElementById("d_levels").value || "").trim();
    await api("/api/dca", {{
      method: "POST",
      body: JSON.stringify({{ ticker, levels }})
    }});
    log(`DCA guardado: ${ticker}`);
    renderDca((await api("/api/dca")).items);
  }};

  document.getElementById("btnDelDca").onclick = async () => {{
    const ticker = (document.getElementById("d_ticker").value || "").trim().toUpperCase();
    await api("/api/dca/" + encodeURIComponent(ticker), {{ method: "DELETE" }});
    log(`DCA eliminado: ${ticker}`);
    renderDca((await api("/api/dca")).items);
  }};

  document.getElementById("btnLoadDca").onclick = async () => {{
    renderDca((await api("/api/dca")).items);
  }};

  // ===== Monday plan =====
  function renderMonday(items) {{
    const box = document.getElementById("mondayList");
    if (!items.length) {{
      box.innerHTML = "<div>Sin plan lunes todavía.</div>";
      return;
    }}
    const total = items.reduce((s, it) => s + Number(it.amount || 0), 0);
    box.innerHTML =
      `<div><b>Total:</b> ${total}</div>` +
      items.map(x => `<div>🏆 <b>${x.ticker}</b> — ${x.amount}</div>`).join("");
  }}

  document.getElementById("btnSaveMonday").onclick = async () => {{
    const ticker = (document.getElementById("m_ticker").value || "").trim().toUpperCase();
    const amount = Number(document.getElementById("m_amount").value || 0);
    await api("/api/monday", {{
      method: "POST",
      body: JSON.stringify({{ ticker, amount }})
    }});
    log(`Plan lunes guardado: ${ticker} ${amount}`);
    renderMonday((await api("/api/monday")).items);
  }};

  document.getElementById("btnDelMonday").onclick = async () => {{
    const ticker = (document.getElementById("m_ticker").value || "").trim().toUpperCase();
    await api("/api/monday/" + encodeURIComponent(ticker), {{ method: "DELETE" }});
    log(`Plan lunes eliminado: ${ticker}`);
    renderMonday((await api("/api/monday")).items);
  }};

  document.getElementById("btnLoadMonday").onclick = async () => {{
    renderMonday((await api("/api/monday")).items);
  }};

  // ===== Priority =====
  function renderPriority(items) {{
    const box = document.getElementById("priorityBox");
    if (!items.length) {{
      box.innerHTML = "<div>Sin prioridad guardada.</div>";
      return;
    }}
    box.innerHTML = "<div>🥇 Orden:</div>" + items.map((t,i)=>`<div>${i+1}. <b>${t}</b></div>`).join("");
  }}

  document.getElementById("btnSavePriority").onclick = async () => {{
    const order = (document.getElementById("p_order").value || "").trim();
    await api("/api/priority", {{
      method: "POST",
      body: JSON.stringify({{ order }})
    }});
    log("Prioridad guardada ✅");
    renderPriority((await api("/api/priority")).items);
  }};

  document.getElementById("btnLoadPriority").onclick = async () => {{
    renderPriority((await api("/api/priority")).items);
  }};

  // ===== Quick config =====
  document.getElementById("btnQuick").onclick = async () => {{
    // ✅ tu setup (70 lunes / 40 dips)
    await api("/api/budget", {{
      method: "POST",
      body: JSON.stringify({{ weekly_budget: 70, dip_budget: 40 }})
    }});

    // ✅ alertas recomendadas (ajustables)
    const alerts = [
      {{ ticker: "IVES", drop_pct: 5 }},
      {{ ticker: "JEPQ", drop_pct: 5 }},
      {{ ticker: "SCHD", drop_pct: 7 }},
      {{ ticker: "QQQ",  drop_pct: 10 }},
      {{ ticker: "NVDA", drop_pct: 15 }},
    ];
    for (const a of alerts) {{
      await api("/api/alerts", {{ method:"POST", body: JSON.stringify({{...a, enabled:true}}) }});
    }}

    // ✅ prioridad
    await api("/api/priority", {{
      method:"POST",
      body: JSON.stringify({{ order: "NVDA QQQ JEPQ SCHD IVES" }})
    }});

    log("Configuración rápida aplicada 🔥");
  }};

  initAll();
</script>
</body>
</html>
"""


# =========================
# API
# =========================
@app.get("/api/me")
def api_me(req: Request):
    u = require_user(req)
    upsert_user(u)
    return {
        "telegram_user_id": u["telegram_user_id"],
        "username": u.get("username"),
        "first_name": u.get("first_name"),
        "last_name": u.get("last_name"),
    }


@app.get("/api/budget")
def get_budget(req: Request):
    u = require_user(req)
    upsert_user(u)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT weekly_budget, dip_budget FROM users WHERE telegram_user_id=%s", (u["telegram_user_id"],))
            row = cur.fetchone() or {"weekly_budget": 0, "dip_budget": 0}
            return row


@app.post("/api/budget")
async def set_budget(req: Request):
    u = require_user(req)
    upsert_user(u)
    body = await req.json()
    weekly = float(body.get("weekly_budget", 0) or 0)
    dip = float(body.get("dip_budget", 0) or 0)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET weekly_budget=%s, dip_budget=%s, updated_at=now()
                WHERE telegram_user_id=%s
            """, (weekly, dip, u["telegram_user_id"]))
    return {"ok": True, "weekly_budget": weekly, "dip_budget": dip}


@app.get("/api/alerts")
def list_alerts(req: Request):
    u = require_user(req)
    upsert_user(u)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ticker, drop_pct, enabled
                FROM alerts
                WHERE telegram_user_id=%s
                ORDER BY ticker ASC
            """, (u["telegram_user_id"],))
            items = cur.fetchall() or []
    return {"items": items}


@app.post("/api/alerts")
async def upsert_alert(req: Request):
    u = require_user(req)
    upsert_user(u)
    body = await req.json()
    ticker = (body.get("ticker") or "").strip().upper()
    drop_pct = float(body.get("drop_pct", 0) or 0)
    enabled = bool(body.get("enabled", True))

    if not ticker:
        raise HTTPException(status_code=400, detail="Missing ticker")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (telegram_user_id, ticker, drop_pct, enabled)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (telegram_user_id, ticker) DO UPDATE SET
                    drop_pct=EXCLUDED.drop_pct,
                    enabled=EXCLUDED.enabled
            """, (u["telegram_user_id"], ticker, drop_pct, enabled))
    return {"ok": True}


@app.delete("/api/alerts/{ticker}")
def delete_alert(ticker: str, req: Request):
    u = require_user(req)
    upsert_user(u)
    t = (ticker or "").strip().upper()
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts WHERE telegram_user_id=%s AND ticker=%s", (u["telegram_user_id"], t))
    return {"ok": True}


def parse_levels(levels_str: str) -> List[str]:
    # devuelve tokens tipo ["15:15", "25:25", "35:40"]
    tokens = [x.strip() for x in (levels_str or "").replace(",", " ").split() if x.strip()]
    for tok in tokens:
        if ":" not in tok:
            raise HTTPException(status_code=400, detail=f"Bad level format: {tok} (use drop:amount)")
    return tokens


@app.get("/api/dca")
def list_dca(req: Request):
    u = require_user(req)
    upsert_user(u)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ticker, levels_json
                FROM dca_rules
                WHERE telegram_user_id=%s
                ORDER BY ticker ASC
            """, (u["telegram_user_id"],))
            rows = cur.fetchall() or []
    items = []
    for r in rows:
        try:
            levels = json.loads(r["levels_json"] or "[]")
        except Exception:
            levels = []
        items.append({"ticker": r["ticker"], "levels": levels})
    return {"items": items}


@app.post("/api/dca")
async def upsert_dca(req: Request):
    u = require_user(req)
    upsert_user(u)
    body = await req.json()
    ticker = (body.get("ticker") or "").strip().upper()
    levels_str = (body.get("levels") or "").strip()

    if not ticker:
        raise HTTPException(status_code=400, detail="Missing ticker")

    levels = parse_levels(levels_str)
    levels_json = json.dumps(levels)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO dca_rules (telegram_user_id, ticker, levels_json)
                VALUES (%s, %s, %s)
                ON CONFLICT (telegram_user_id, ticker) DO UPDATE SET
                    levels_json=EXCLUDED.levels_json
            """, (u["telegram_user_id"], ticker, levels_json))
    return {"ok": True}


@app.delete("/api/dca/{ticker}")
def delete_dca(ticker: str, req: Request):
    u = require_user(req)
    upsert_user(u)
    t = (ticker or "").strip().upper()
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM dca_rules WHERE telegram_user_id=%s AND ticker=%s", (u["telegram_user_id"], t))
    return {"ok": True}


@app.get("/api/monday")
def list_monday(req: Request):
    u = require_user(req)
    upsert_user(u)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT ticker, amount
                FROM monday_plan
                WHERE telegram_user_id=%s
                ORDER BY ticker ASC
            """, (u["telegram_user_id"],))
            items = cur.fetchall() or []
    return {"items": items}


@app.post("/api/monday")
async def upsert_monday(req: Request):
    u = require_user(req)
    upsert_user(u)
    body = await req.json()
    ticker = (body.get("ticker") or "").strip().upper()
    amount = float(body.get("amount", 0) or 0)

    if not ticker:
        raise HTTPException(status_code=400, detail="Missing ticker")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO monday_plan (telegram_user_id, ticker, amount)
                VALUES (%s, %s, %s)
                ON CONFLICT (telegram_user_id, ticker) DO UPDATE SET
                    amount=EXCLUDED.amount
            """, (u["telegram_user_id"], ticker, amount))
    return {"ok": True}


@app.delete("/api/monday/{ticker}")
def delete_monday(ticker: str, req: Request):
    u = require_user(req)
    upsert_user(u)
    t = (ticker or "").strip().upper()
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM monday_plan WHERE telegram_user_id=%s AND ticker=%s", (u["telegram_user_id"], t))
    return {"ok": True}


@app.get("/api/priority")
def get_priority(req: Request):
    u = require_user(req)
    upsert_user(u)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT priority_json FROM settings WHERE telegram_user_id=%s", (u["telegram_user_id"],))
            row = cur.fetchone()
            if not row:
                return {"items": []}
            try:
                items = json.loads(row["priority_json"] or "[]")
            except Exception:
                items = []
            return {"items": items}


@app.post("/api/priority")
async def set_priority(req: Request):
    u = require_user(req)
    upsert_user(u)

    body = await req.json()
    order = (body.get("order") or "").strip()
    items = [x.strip().upper() for x in order.replace(",", " ").split() if x.strip()]

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO settings (telegram_user_id, priority_json)
                VALUES (%s, %s)
                ON CONFLICT (telegram_user_id) DO UPDATE SET
                    priority_json=EXCLUDED.priority_json
            """, (u["telegram_user_id"], json.dumps(items)))
    return {"ok": True, "items": items}


# Healthcheck
@app.get("/health")
def health():
    return {"ok": True}
