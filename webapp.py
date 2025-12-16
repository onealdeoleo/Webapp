import os, json, hmac, hashlib
from urllib.parse import parse_qsl
from typing import Dict, Any, List

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import psycopg2
import os

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
APP_TITLE = os.getenv("APP_TITLE", "Robinhood_alert Dashboard")

if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN env var")
if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL env var")

app = FastAPI()


# ---------------------------
# Telegram Mini App auth
# ---------------------------
def verify_telegram_init_data(init_data: str) -> Dict[str, Any]:
    """
    Verifies Telegram WebApp initData (HMAC check).
    Returns parsed fields if valid, else raises.
    """
    if not init_data or "hash=" not in init_data:
        raise HTTPException(status_code=401, detail="Missing initData")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", "")

    # Build data_check_string
    data_check_string = "\n".join([f"{k}={pairs[k]}" for k in sorted(pairs.keys())])

    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    if calculated_hash != received_hash:
        raise HTTPException(status_code=401, detail="Bad initData signature")

    # user is a JSON string
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


# ---------------------------
# DB helpers
# ---------------------------
conn = psycopg2.connect(os.environ["DATABASE_URL"])
return conn

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

            CREATE TABLE IF NOT EXISTS alerts (
                telegram_user_id BIGINT NOT NULL,
                ticker TEXT NOT NULL,
                buy_drop_pct NUMERIC DEFAULT 0,   -- % drop from 60d high
                entry_price NUMERIC,              -- optional
                tp_pct NUMERIC,                   -- take profit %
                sl_pct NUMERIC,                   -- stop loss %
                dca_json TEXT DEFAULT '[]',        -- [{"drop":10,"amount":15}, ...]
                PRIMARY KEY (telegram_user_id, ticker)
            );

            CREATE TABLE IF NOT EXISTS plans (
                telegram_user_id BIGINT NOT NULL,
                ticker TEXT NOT NULL,
                amount NUMERIC NOT NULL,
                PRIMARY KEY (telegram_user_id, ticker)
            );
            """)
        conn.commit()

init_db()


def upsert_user(u: Dict[str, Any]):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (telegram_user_id, username, first_name, last_name)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (telegram_user_id)
                DO UPDATE SET username=EXCLUDED.username, first_name=EXCLUDED.first_name, last_name=EXCLUDED.last_name
            """, (u["telegram_user_id"], u["username"], u["first_name"], u["last_name"]))
        conn.commit()


def get_state(user_id: int) -> Dict[str, Any]:
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT weekly_budget, dip_budget FROM users WHERE telegram_user_id=%s", (user_id,))
            row = cur.fetchone()
            budgets = {"weekly_budget": float(row[0]), "dip_budget": float(row[1])} if row else {"weekly_budget": 0, "dip_budget": 0}

            cur.execute("""
                SELECT ticker, buy_drop_pct, entry_price, tp_pct, sl_pct, dca_json
                FROM alerts WHERE telegram_user_id=%s ORDER BY ticker
            """, (user_id,))
            alerts = []
            for t, buy, entry, tp, sl, dca_json in cur.fetchall():
                alerts.append({
                    "ticker": t,
                    "buy_drop_pct": float(buy or 0),
                    "entry_price": float(entry) if entry is not None else None,
                    "tp_pct": float(tp) if tp is not None else None,
                    "sl_pct": float(sl) if sl is not None else None,
                    "dca": json.loads(dca_json or "[]"),
                })

            cur.execute("SELECT ticker, amount FROM plans WHERE telegram_user_id=%s ORDER BY ticker", (user_id,))
            plans = [{"ticker": t, "amount": float(a)} for (t, a) in cur.fetchall()]

    return {"budgets": budgets, "alerts": alerts, "plans": plans}


# ---------------------------
# UI (single-file HTML + JS)
# ---------------------------
def page_html() -> str:
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{APP_TITLE}</title>
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    body {{ font-family: -apple-system, system-ui, Arial; margin: 16px; }}
    .card {{ border: 1px solid #ddd; border-radius: 12px; padding: 12px; margin-bottom: 12px; }}
    input, button {{ padding: 10px; border-radius: 10px; border: 1px solid #ccc; }}
    button {{ border: 0; background: #111; color: white; }}
    .row {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .row > * {{ flex: 1; min-width: 140px; }}
    pre {{ background:#f7f7f7; padding:12px; border-radius:12px; overflow:auto; }}
  </style>
</head>
<body>
  <h2>{APP_TITLE}</h2>
  <div id="me" class="card">Cargando…</div>

  <div class="card">
    <h3>Presupuesto</h3>
    <div class="row">
      <input id="weekly" type="number" step="1" placeholder="Semanal (ej 70)"/>
      <input id="dip" type="number" step="1" placeholder="Dips (ej 40)"/>
      <button onclick="setBudget()">Guardar</button>
    </div>
  </div>

  <div class="card">
    <h3>Agregar / actualizar alerta</h3>
    <div class="row">
      <input id="ticker" placeholder="Ticker (QQQ)"/>
      <input id="buy" type="number" step="0.1" placeholder="BUY drop% (10)"/>
      <input id="tp" type="number" step="0.1" placeholder="TP% (10)"/>
      <input id="sl" type="number" step="0.1" placeholder="SL% (7)"/>
      <input id="entry" type="number" step="0.01" placeholder="Entry (opcional)"/>
      <button onclick="upsertAlert()">Guardar</button>
    </div>
    <p style="margin-top:8px;">DCA ejemplo: <b>10:15 15:25 20:40</b></p>
    <div class="row">
      <input id="dca" placeholder="DCA (10:15 15:25)"/>
      <button onclick="setDca()">Guardar DCA</button>
    </div>
  </div>

  <div class="card">
    <h3>Plan fijo lunes (DCA semanal)</h3>
    <p>Ejemplo: QQQ 30, SCHD 20, JEPQ 20</p>
    <div class="row">
      <input id="planTicker" placeholder="Ticker (QQQ)"/>
      <input id="planAmount" type="number" step="1" placeholder="Monto (30)"/>
      <button onclick="setPlan()">Guardar</button>
    </div>
  </div>

  <div class="card">
    <h3>Estado</h3>
    <button onclick="refresh()">Refrescar</button>
    <button onclick="removeTicker()">Eliminar ticker</button>
    <input id="remove" placeholder="Ticker a eliminar (QQQ)" style="margin-top:8px; width:100%;"/>
    <pre id="state"></pre>
  </div>

<script>
  const tg = window.Telegram.WebApp;
  tg.expand();

  async function api(path, payload={{}}) {{
    const initData = tg.initData || "";
    const res = await fetch(path, {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ initData, ...payload }})
    }});
    const data = await res.json();
    if (!res.ok) {{
      alert("Error: " + (data.detail || JSON.stringify(data)));
      throw new Error(data.detail || "api error");
    }}
    return data;
  }}

  async function refresh() {{
    const data = await api("/api/bootstrap", {{}});
    document.getElementById("me").innerHTML =
      "👤 <b>" + (data.user.username ? "@"+data.user.username : data.user.first_name) + "</b> (ID " + data.user.telegram_user_id + ")";
    document.getElementById("weekly").value = data.state.budgets.weekly_budget || "";
    document.getElementById("dip").value = data.state.budgets.dip_budget || "";
    document.getElementById("state").textContent = JSON.stringify(data.state, null, 2);
  }}

  async function setBudget() {{
    await api("/api/setbudget", {{
      weekly: Number(document.getElementById("weekly").value || 0),
      dip: Number(document.getElementById("dip").value || 0),
    }});
    await refresh();
  }}

  async function upsertAlert() {{
    await api("/api/upsert_alert", {{
      ticker: document.getElementById("ticker").value,
      buy_drop_pct: Number(document.getElementById("buy").value || 0),
      tp_pct: Number(document.getElementById("tp").value || 0),
      sl_pct: Number(document.getElementById("sl").value || 0),
      entry_price: document.getElementById("entry").value ? Number(document.getElementById("entry").value) : null
    }});
    await refresh();
  }}

  async function setDca() {{
    await api("/api/setdca", {{
      ticker: document.getElementById("ticker").value,
      dca: document.getElementById("dca").value
    }});
    await refresh();
  }}

  async function setPlan() {{
    await api("/api/setplan", {{
      ticker: document.getElementById("planTicker").value,
      amount: Number(document.getElementById("planAmount").value || 0)
    }});
    await refresh();
  }}

  async function removeTicker() {{
    await api("/api/remove", {{ ticker: document.getElementById("remove").value }});
    await refresh();
  }}

  refresh();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return page_html()


# ---------------------------
# API endpoints
# ---------------------------
@app.post("/api/bootstrap")
async def bootstrap(req: Request):
    body = await req.json()
    info = verify_telegram_init_data(body.get("initData", ""))
    upsert_user(info)
    state = get_state(info["telegram_user_id"])
    return {"user": {
        "telegram_user_id": info["telegram_user_id"],
        "username": info["username"],
        "first_name": info["first_name"],
        "last_name": info["last_name"],
    }, "state": state}


@app.post("/api/setbudget")
async def setbudget(req: Request):
    body = await req.json()
    info = verify_telegram_init_data(body.get("initData", ""))
    upsert_user(info)

    weekly = float(body.get("weekly", 0))
    dip = float(body.get("dip", 0))

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users SET weekly_budget=%s, dip_budget=%s
                WHERE telegram_user_id=%s
            """, (weekly, dip, info["telegram_user_id"]))
        conn.commit()

    return {"ok": True}


@app.post("/api/upsert_alert")
async def upsert_alert(req: Request):
    body = await req.json()
    info = verify_telegram_init_data(body.get("initData", ""))
    upsert_user(info)

    ticker = (body.get("ticker") or "").upper().strip()
    if not ticker:
        raise HTTPException(400, "ticker required")

    buy = float(body.get("buy_drop_pct", 0))
    tp = float(body.get("tp_pct", 0)) if body.get("tp_pct") is not None else None
    sl = float(body.get("sl_pct", 0)) if body.get("sl_pct") is not None else None
    entry = body.get("entry_price", None)
    entry = float(entry) if entry is not None else None

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (telegram_user_id, ticker, buy_drop_pct, entry_price, tp_pct, sl_pct)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (telegram_user_id, ticker)
                DO UPDATE SET buy_drop_pct=EXCLUDED.buy_drop_pct,
                              entry_price=EXCLUDED.entry_price,
                              tp_pct=EXCLUDED.tp_pct,
                              sl_pct=EXCLUDED.sl_pct
            """, (info["telegram_user_id"], ticker, buy, entry, tp, sl))
        conn.commit()

    return {"ok": True}


@app.post("/api/setdca")
async def setdca(req: Request):
    body = await req.json()
    info = verify_telegram_init_data(body.get("initData", ""))
    upsert_user(info)

    ticker = (body.get("ticker") or "").upper().strip()
    raw = (body.get("dca") or "").strip()
    if not ticker:
        raise HTTPException(400, "ticker required")

    # raw like: "10:15 15:25 20:40"
    items = []
    if raw:
        for part in raw.split():
            if ":" not in part:
                continue
            d, a = part.split(":", 1)
            items.append({"drop": float(d), "amount": float(a)})

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE alerts SET dca_json=%s
                WHERE telegram_user_id=%s AND ticker=%s
            """, (json.dumps(items), info["telegram_user_id"], ticker))
        conn.commit()

    return {"ok": True, "items": items}


@app.post("/api/setplan")
async def setplan(req: Request):
    body = await req.json()
    info = verify_telegram_init_data(body.get("initData", ""))
    upsert_user(info)

    ticker = (body.get("ticker") or "").upper().strip()
    amount = float(body.get("amount", 0))
    if not ticker or amount <= 0:
        raise HTTPException(400, "ticker + amount required")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO plans (telegram_user_id, ticker, amount)
                VALUES (%s, %s, %s)
                ON CONFLICT (telegram_user_id, ticker)
                DO UPDATE SET amount=EXCLUDED.amount
            """, (info["telegram_user_id"], ticker, amount))
        conn.commit()

    return {"ok": True}


@app.post("/api/remove")
async def remove(req: Request):
    body = await req.json()
    info = verify_telegram_init_data(body.get("initData", ""))
    upsert_user(info)

    ticker = (body.get("ticker") or "").upper().strip()
    if not ticker:
        raise HTTPException(400, "ticker required")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM alerts WHERE telegram_user_id=%s AND ticker=%s", (info["telegram_user_id"], ticker))
            cur.execute("DELETE FROM plans  WHERE telegram_user_id=%s AND ticker=%s", (info["telegram_user_id"], ticker))
        conn.commit()

    return {"ok": True}
