import os
import json
import hmac
import hashlib
from urllib.parse import parse_qsl
from typing import Dict, Any

import psycopg
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
# =========================================================
# ENV VARS
# =========================================================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
APP_TITLE = os.getenv("APP_TITLE", "Robinhood Alert Dashboard")

if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN env var")
if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL env var")

# =========================================================
# FASTAPI APP
# =========================================================
app = FastAPI(title=APP_TITLE)

# ✅ AQUÍ VA EXACTAMENTE
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h2>✅ Robinhood_alert Dashboard</h2>
    <p>Tu servicio está corriendo.</p>
    <p>Abre esta app desde Telegram (Mini App).</p>
    """



# =========================================================
# DB HELPERS (psycopg v3)
# =========================================================
def db():
    # psycopg v3 connection
    return psycopg.connect(DATABASE_URL)

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
                buy_drop_pct NUMERIC DEFAULT 0,
                entry_price NUMERIC,
                tp_pct NUMERIC,
                sl_pct NUMERIC,
                dca_json TEXT DEFAULT '[]',
                PRIMARY KEY (telegram_user_id, ticker)
            );
            """)
        conn.commit()

# Init tables on startup
init_db()

# =========================================================
# TELEGRAM MINI APP AUTH (CORRECTO)
# =========================================================
def verify_telegram_init_data(init_data: str) -> Dict[str, Any]:
    if not init_data or "hash=" not in init_data:
        raise HTTPException(status_code=401, detail="Missing initData")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", "")

    data_check_string = "\n".join(
        f"{k}={pairs[k]}" for k in sorted(pairs.keys())
    )

    # ✅ Telegram WebApp secret key
    secret_key = hmac.new(
        b"WebAppData",
        TELEGRAM_BOT_TOKEN.encode(),
        hashlib.sha256
    ).digest()

    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise HTTPException(status_code=401, detail="Bad initData signature")

    user_raw = pairs.get("user")
    if not user_raw:
        raise HTTPException(status_code=401, detail="No user in initData")

    user = json.loads(user_raw)

    return {
        "telegram_user_id": int(user.get("id")),
        "username": user.get("username"),
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
    }

# =========================================================
# ENDPOINTS
# =========================================================
@app.get("/health")
def health():
    return {"status": "ok", "app": APP_TITLE}

@app.post("/api/bootstrap")
async def bootstrap(request: Request):
    body = await request.json()
    init_data = body.get("initData", "")

    tg = verify_telegram_init_data(init_data)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            INSERT INTO users (telegram_user_id, username, first_name, last_name)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (telegram_user_id)
            DO UPDATE SET
                username = EXCLUDED.username,
                first_name = EXCLUDED.first_name,
                last_name = EXCLUDED.last_name;
            """, (
                tg["telegram_user_id"],
                tg["username"],
                tg["first_name"],
                tg["last_name"],
            ))
        conn.commit()

    return JSONResponse({"ok": True, "user": tg})
