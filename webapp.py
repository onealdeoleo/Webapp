import os
import json
import hmac
import hashlib
from urllib.parse import parse_qsl
from typing import Dict, Any

import psycopg
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

# ---------------------------
# ENV
# ---------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
APP_TITLE = os.getenv("APP_TITLE", "Robinhood Alert Dashboard")

if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN env var")

if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL env var")

# ---------------------------
# APP
# ---------------------------
app = FastAPI(title=APP_TITLE)

# ---------------------------
# DB helper (psycopg v3)
# ---------------------------
def get_conn():
    return psycopg.connect(DATABASE_URL)

# ---------------------------
# Telegram Mini App auth
# ---------------------------
def verify_telegram_init_data(init_data: str) -> Dict[str, Any]:
    if not init_data or "hash=" not in init_data:
        raise HTTPException(status_code=401, detail="Missing initData")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", "")

    data_check_string = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs.keys()))

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

# ---------------------------
# HOME / DASHBOARD
# ---------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Robinhood Alert Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />

  <style>
    body {
      background: #020617;
      color: #e5e7eb;
      font-family: Arial, sans-serif;
      padding: 20px;
    }
    h2 { color: #22c55e; }
    .card {
      background: #020617;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 16px;
    }
    button {
      width: 100%;
      padding: 12px;
      margin-top: 8px;
      border-radius: 8px;
      border: none;
      background: #22c55e;
      color: #022c22;
      font-weight: bold;
      cursor: pointer;
    }
    button.secondary {
      background: #0ea5e9;
      color: #020617;
    }
  </style>
</head>

<body>

<h2>📊 Robinhood Alert Bot</h2>

<div class="card">
  <p><b>Estado:</b> Mini App activa ✅</p>
  <p>Controla tu bot desde Telegram.</p>
</div>

<div class="card">
  <h3>💰 Presupuesto</h3>
  <button onclick="alert('Configura con /setbudget en Telegram')">
    Set Budget
  </button>
</div>

<div class="card">
  <h3>📉 DCA Inteligente</h3>
  <button class="secondary" onclick="alert('Configura con /dca en Telegram')">
    DCA Rules
  </button>
</div>

<div class="card">
  <h3>⭐ Prioridad</h3>
  <button onclick="alert('Usa /priority en Telegram')">
    Set Priority
  </button>
</div>

<script>
  // Telegram Mini App safe init
  if (window.Telegram && window.Telegram.WebApp) {
    Telegram.WebApp.ready();
    Telegram.WebApp.expand();
  }
</script>

</body>
</html>
"""

# ---------------------------
# API example (JSON)
# ---------------------------
@app.get("/health", response_class=JSONResponse)
def health():
    return {"status": "ok"}
