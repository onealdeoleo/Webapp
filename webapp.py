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


TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
APP_TITLE = os.getenv("APP_TITLE", "Robinhood_alert Dashboard")

if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN env var")
if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL env var")

app = FastAPI(title=APP_TITLE)


# ---------------------------
# Telegram Mini App auth
# ---------------------------
def verify_telegram_init_data(init_data: str) -> Dict[str, Any]:
    """
    Verifies Telegram WebApp initData (HMAC check).
    Telegram official secret:
      secret_key = HMAC_SHA256("WebAppData", bot_token)
    """
    if not init_data or "hash=" not in init_data:
        raise HTTPException(status_code=401, detail="Missing initData")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", "")

    data_check_string = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs.keys()))

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


def get_init_data_from_request(request: Request) -> str:
    # Prefer header from our frontend fetch
    init_data = request.headers.get("x-telegram-initdata", "").strip()
    if init_data:
        return init_data

    # Fallback: query string ?initData=...
    init_data_q = request.query_params.get("initData", "").strip()
    if init_data_q:
        return init_data_q

    # Fallback: some people use "init_data"
    init_data_q2 = request.query_params.get("init_data", "").strip()
    if init_data_q2:
        return init_data_q2

    return ""


# ---------------------------
# DB helpers (psycopg v3)
# ---------------------------
def db():
    # dict_row => cursor returns dicts
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


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
                dip_budget NUMERIC DEFAULT 0
            );
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                telegram_user_id BIGINT NOT NULL,
                ticker TEXT NOT NULL,
                drop_pct NUMERIC DEFAULT 0,
                PRIMARY KEY (telegram_user_id, ticker)
            );
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS dca_rules (
                telegram_user_id BIGINT NOT NULL,
                ticker TEXT NOT NULL,
                rules_json TEXT NOT NULL,
                PRIMARY KEY (telegram_user_id, ticker)
            );
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS monday_plan (
                telegram_user_id BIGINT NOT NULL,
                ticker TEXT NOT NULL,
                amount NUMERIC DEFAULT 0,
                PRIMARY KEY (telegram_user_id, ticker)
            );
            """)

        conn.commit()


@app.on_event("startup")
def _startup():
    init_db()


# ---------------------------
# UI (Dashboard con botones)
# ---------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{APP_TITLE}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    :root {{
      --bg: var(--tg-theme-bg-color, #0b1220);
      --text: var(--tg-theme-text-color, #e5e7eb);
      --hint: var(--tg-theme-hint-color, #94a3b8);
      --btn: var(--tg-theme-button-color, #22c55e);
      --btnText: var(--tg-theme-button-text-color, #0b1220);
      --card: rgba(255,255,255,0.06);
      --border: rgba(255,255,255,0.10);
    }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial;
      background: var(--bg);
      color: var(--text);
      padding: 14px;
    }}
    h2 {{ margin: 6px 0 12px; }}
    .hint {{ color: var(--hint); font-size: 13px; margin-bottom: 14px; }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
      max-width: 720px;
      margin: 0 auto;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 12px;
    }}
    .row {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }}
    input {{
      width: 100%;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: rgba(0,0,0,0.18);
      color: var(--text);
      outline: none;
      box-sizing: border-box;
    }}
    button {{
      width: 100%;
      padding: 12px;
      border: none;
      border-radius: 12px;
      background: var(--btn);
      color: var(--btnText);
      font-weight: 700;
      cursor: pointer;
    }}
    .mini {{
      font-size: 12px;
      color: var(--hint);
      margin-top: 8px;
      line-height: 1.3;
    }}
    .status {{
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New";
      font-size: 12px;
      color: var(--hint);
      margin-top: 10px;
      border-top: 1px dashed var(--border);
      padding-top: 10px;
    }}
    .pill {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(34,197,94,0.15);
      border: 1px solid rgba(34,197,94,0.25);
      color: #86efac;
      font-size: 12px;
      font-weight: 700;
    }}
  </style>
</head>
<body>
  <div class="grid">
    <div>
      <h2>📊 {APP_TITLE}</h2>
      <div class="hint">Panel con botones. Abre esto desde Telegram (Mini App). ✅</div>
      <div class="pill" id="userPill">Cargando usuario...</div>
    </div>

    <div class="card">
      <h3>💰 Presupuesto</h3>
      <div class="row">
        <input id="weekly" placeholder="Semanal (ej 70)" inputmode="decimal" />
        <input id="dip" placeholder="Dips (ej 40)" inputmode="decimal" />
      </div>
      <div style="height:10px"></div>
      <button onclick="saveBudget()">Guardar Presupuesto</button>
      <div class="mini">Esto alimenta tu bot: <b>/setbudget semanal dips</b></div>
      <div class="status" id="budgetStatus"></div>
    </div>

    <div class="card">
      <h3>📌 Alertas por caída</h3>
      <div class="row">
        <input id="alertTicker" placeholder="Ticker (QQQ/NVDA/JEPQ/SCHD)" />
        <input id="alertDrop" placeholder="Caída % (ej 10)" inputmode="decimal" />
      </div>
      <div style="height:10px"></div>
      <button onclick="saveAlert()">Guardar/Actualizar Alerta</button>
      <div class="mini">Equivale al bot: <b>/add TICKER %</b></div>
      <div class="status" id="alertStatus"></div>
    </div>

    <div class="card">
      <h3>🧠 DCA Inteligente</h3>
      <div class="row">
        <input id="dcaTicker" placeholder="Ticker (NVDA/QQQ/etc)" />
        <input id="dcaRules" placeholder="Reglas ej: 15:15 25:25 35:40" />
      </div>
      <div style="height:10px"></div>
      <button onclick="saveDCA()">Guardar DCA</button>
      <div class="mini">Equivale al bot: <b>/dca TICKER 15:15 25:25 35:40</b></div>
      <div class="status" id="dcaStatus"></div>
    </div>

    <div class="card">
      <h3>🗓️ Plan fijo lunes</h3>
      <div class="row">
        <input id="planTicker" placeholder="Ticker (QQQ/SCHD/JEPQ/IVES)" />
        <input id="planAmount" placeholder="Monto (ej 20)" inputmode="decimal" />
      </div>
      <div style="height:10px"></div>
      <button onclick="savePlan()">Guardar en Plan Lunes</button>
      <div class="mini">Equivale al bot: <b>/plan QQQ 30 SCHD 20 JEPQ 20</b> (aquí lo guardas 1 por 1)</div>
      <div class="status" id="planStatus"></div>
    </div>

    <div class="card">
      <h3>✅ Resumen</h3>
      <button onclick="refreshAll()">Actualizar / Ver todo</button>
      <div class="status" id="allStatus"></div>
    </div>
  </div>

<script>
  const tg = window.Telegram?.WebApp;
  if (tg) {{
    tg.ready();
    tg.expand();
  }}

  function initData() {{
    return tg?.initData || "";
  }}

  async function api(path, payload=null) {{
    const opts = {{
      method: payload ? "POST" : "GET",
      headers: {{
        "Content-Type": "application/json",
        "X-Telegram-InitData": initData()
      }}
    }};
    if (payload) opts.body = JSON.stringify(payload);

    const res = await fetch(path, opts);
    const text = await res.text();
    let data;
    try {{ data = JSON.parse(text); }} catch(e) {{ data = {{ raw: text }}; }}
    if (!res.ok) throw new Error(data?.detail || data?.error || text);
    return data;
  }}

  function setStatus(id, msg) {{
    document.getElementById(id).textContent = msg;
  }}

  async function loadMe() {{
    try {{
      const me = await api("/api/me");
      document.getElementById("userPill").textContent =
        `👤 ${me.first_name || ""} ${me.last_name || ""} (@${me.username || "sin_user"}) • ID ${me.telegram_user_id}`;
      // precargar budgets
      document.getElementById("weekly").value = me.weekly_budget ?? 0;
      document.getElementById("dip").value = me.dip_budget ?? 0;
    }} catch (e) {{
      document.getElementById("userPill").textContent = "❌ Error auth: " + e.message;
    }}
  }}

  async function saveBudget() {{
    setStatus("budgetStatus", "Guardando...");
    try {{
      const weekly = Number(document.getElementById("weekly").value || 0);
      const dip = Number(document.getElementById("dip").value || 0);
      const out = await api("/api/budget", {{ weekly_budget: weekly, dip_budget: dip }});
      setStatus("budgetStatus", "✅ Guardado: " + JSON.stringify(out, null, 2));
    }} catch (e) {{
      setStatus("budgetStatus", "❌ " + e.message);
    }}
  }}

  async function saveAlert() {{
    setStatus("alertStatus", "Guardando...");
    try {{
      const ticker = (document.getElementById("alertTicker").value || "").trim().toUpperCase();
      const drop_pct = Number(document.getElementById("alertDrop").value || 0);
      const out = await api("/api/alert", {{ ticker, drop_pct }});
      setStatus("alertStatus", "✅ Guardado: " + JSON.stringify(out, null, 2));
    }} catch (e) {{
      setStatus("alertStatus", "❌ " + e.message);
    }}
  }}

  async function saveDCA() {{
    setStatus("dcaStatus", "Guardando...");
    try {{
      const ticker = (document.getElementById("dcaTicker").value || "").trim().toUpperCase();
      const rules = (document.getElementById("dcaRules").value || "").trim();
      const out = await api("/api/dca", {{ ticker, rules }});
      setStatus("dcaStatus", "✅ Guardado: " + JSON.stringify(out, null, 2));
    }} catch (e) {{
      setStatus("dcaStatus", "❌ " + e.message);
    }}
  }}

  async function savePlan() {{
    setStatus("planStatus", "Guardando...");
    try {{
      const ticker = (document.getElementById("planTicker").value || "").trim().toUpperCase();
      const amount = Number(document.getElementById("planAmount").value || 0);
      const out = await api("/api/plan", {{ ticker, amount }});
      setStatus("planStatus", "✅ Guardado: " + JSON.stringify(out, null, 2));
    }} catch (e) {{
      setStatus("planStatus", "❌ " + e.message);
    }}
  }}

  async function refreshAll() {{
    setStatus("allStatus", "Cargando...");
    try {{
      const data = await api("/api/all");
      setStatus("allStatus", "✅ " + JSON.stringify(data, null, 2));
    }} catch (e) {{
      setStatus("allStatus", "❌ " + e.message);
    }}
  }}

  loadMe();
</script>
</body>
</html>
"""


# ---------------------------
# API
# ---------------------------
def ensure_user(u: Dict[str, Any]) -> Dict[str, Any]:
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            INSERT INTO users (telegram_user_id, username, first_name, last_name)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (telegram_user_id) DO UPDATE SET
              username = EXCLUDED.username,
              first_name = EXCLUDED.first_name,
              last_name = EXCLUDED.last_name
            RETURNING telegram_user_id, username, first_name, last_name, weekly_budget, dip_budget;
            """, (
                u["telegram_user_id"],
                u.get("username"),
                u.get("first_name"),
                u.get("last_name"),
            ))
            row = cur.fetchone()
        conn.commit()
    return row


def authed_user(request: Request) -> Dict[str, Any]:
    init_data = get_init_data_from_request(request)
    user = verify_telegram_init_data(init_data)
    return user


@app.get("/api/me", response_class=JSONResponse)
def api_me(request: Request):
    u = authed_user(request)
    row = ensure_user(u)
    return row


@app.post("/api/budget", response_class=JSONResponse)
async def api_budget(request: Request):
    u = authed_user(request)
    body = await request.json()
    weekly = float(body.get("weekly_budget", 0) or 0)
    dip = float(body.get("dip_budget", 0) or 0)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            INSERT INTO users (telegram_user_id, username, first_name, last_name, weekly_budget, dip_budget)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (telegram_user_id) DO UPDATE SET
              weekly_budget = EXCLUDED.weekly_budget,
              dip_budget = EXCLUDED.dip_budget;
            """, (
                u["telegram_user_id"], u.get("username"), u.get("first_name"), u.get("last_name"),
                weekly, dip
            ))
        conn.commit()

    return {"ok": True, "weekly_budget": weekly, "dip_budget": dip}


@app.post("/api/alert", response_class=JSONResponse)
async def api_alert(request: Request):
    u = authed_user(request)
    body = await request.json()
    ticker = (body.get("ticker") or "").strip().upper()
    drop_pct = float(body.get("drop_pct", 0) or 0)

    if not ticker:
        raise HTTPException(status_code=400, detail="Missing ticker")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            INSERT INTO alerts (telegram_user_id, ticker, drop_pct)
            VALUES (%s, %s, %s)
            ON CONFLICT (telegram_user_id, ticker) DO UPDATE SET
              drop_pct = EXCLUDED.drop_pct;
            """, (u["telegram_user_id"], ticker, drop_pct))
        conn.commit()

    return {"ok": True, "ticker": ticker, "drop_pct": drop_pct}


@app.post("/api/dca", response_class=JSONResponse)
async def api_dca(request: Request):
    u = authed_user(request)
    body = await request.json()
    ticker = (body.get("ticker") or "").strip().upper()
    rules = (body.get("rules") or "").strip()

    if not ticker:
        raise HTTPException(status_code=400, detail="Missing ticker")
    if not rules:
        raise HTTPException(status_code=400, detail="Missing rules")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            INSERT INTO dca_rules (telegram_user_id, ticker, rules_json)
            VALUES (%s, %s, %s)
            ON CONFLICT (telegram_user_id, ticker) DO UPDATE SET
              rules_json = EXCLUDED.rules_json;
            """, (u["telegram_user_id"], ticker, rules))
        conn.commit()

    return {"ok": True, "ticker": ticker, "rules": rules}


@app.post("/api/plan", response_class=JSONResponse)
async def api_plan(request: Request):
    u = authed_user(request)
    body = await request.json()
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
              amount = EXCLUDED.amount;
            """, (u["telegram_user_id"], ticker, amount))
        conn.commit()

    return {"ok": True, "ticker": ticker, "amount": amount}


@app.get("/api/all", response_class=JSONResponse)
def api_all(request: Request):
    u = authed_user(request)
    ensure_user(u)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE telegram_user_id=%s", (u["telegram_user_id"],))
            user = cur.fetchone()

            cur.execute("SELECT ticker, drop_pct FROM alerts WHERE telegram_user_id=%s ORDER BY ticker", (u["telegram_user_id"],))
            alerts = cur.fetchall()

            cur.execute("SELECT ticker, rules_json FROM dca_rules WHERE telegram_user_id=%s ORDER BY ticker", (u["telegram_user_id"],))
            dca = cur.fetchall()

            cur.execute("SELECT ticker, amount FROM monday_plan WHERE telegram_user_id=%s ORDER BY ticker", (u["telegram_user_id"],))
            plan = cur.fetchall()

    return {
        "user": user,
        "alerts": alerts,
        "dca": dca,
        "monday_plan": plan,
    }
