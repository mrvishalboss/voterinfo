import base64
import json
import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
# CORS allow karta hai taaki aapki PHP website bina block hue is API ko call kar sake
CORS(app)

BASE = "https://gateway-voters.eci.gov.in"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "applicationName": "ELECTORAL-SEARCH",
    "appName": "ELECTORAL-SEARCH",
    "channelidobo": "ELECTORAL-SEARCH",
    "Origin": "https://electoralsearch.eci.gov.in",
    "Referer": "https://electoralsearch.eci.gov.in/",
}

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArb7++BxL/YN8OIln+6FL
9Gnw5DNmQ/VFZXss+J+TuQyJc891JbqbijxYQNEin2c2u+CnpXpoGQ/1gUSzDMJe
NS3sNSlIUykp2dt7xIm/cmV4sZ/c769vCxVRosMfRaZJnBAah+m1X26lEhnOo0wp
AB9Txr8RIyBe6h7PiQWykeJeh6UacOBBX28kgkq7+vJhW8HgB38lt32XRocznRYw
S9LqR7ZweFmQhTr1+EGrqiEKCOCxMYgHR2SQckb96hZ9kWzfzeun4bUO5oXKJciL
kiS1IgKieADEvYLgu129ZIpn1H+8H+8ikNNVETqEDDMtqcQcQmWppJvcWHaXAs+f
8QIDAQAB
-----END PUBLIC KEY-----"""

PO = "SFfIO0YsOlOKawZe855n97lc4tcPkj7WWsi38yNWpalLBLZzQdkqHWYbZ0=GhSJk2raUo"
PO_SLICE = PO[15:59]

def load_pub():
    return serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())

def b64decode_padded(s: str) -> bytes:
    s = str(s).strip()
    return base64.b64decode(s + "=" * ((-len(s)) % 4))

def encrypt_body(obj: dict) -> dict:
    pub = load_pub()
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    pt = json.dumps(obj, separators=(",", ":")).encode()
    ct = AESGCM(aes_key).encrypt(iv, pt, None)
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "encryptedPayload": base64.b64encode(ct).decode(),
        "encryptedKey": base64.b64encode(enc_key).decode(),
        "iv": base64.b64encode(iv).decode(),
    }

def decrypt_with_po(data_b64: str):
    raw = b64decode_padded(data_b64)
    if len(raw) < 28:
        return None
    key = b64decode_padded(PO_SLICE)
    if len(key) >= 32:
        key = key[:32]
    elif len(key) not in (16, 24, 32):
        key = key.ljust(32, b"\0")[:32]
    try:
        return AESGCM(key).decrypt(raw[:12], raw[12:], None)
    except Exception:
        return None

# API Route 1: Home/Status check
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "API is Active. Use /get_captcha or /search"})

# API Route 2: Fetch Captcha
@app.route('/get_captcha', methods=['GET', 'POST'])
def get_captcha_api():
    try:
        r = requests.get(f"{BASE}/api/v1/captcha-service/getCaptcha/sir", headers=HEADERS, timeout=25)
        r.raise_for_status()
        data_b64 = r.json().get("data") or ""
        pt = decrypt_with_po(data_b64)
        if not pt:
            return jsonify({"success": False, "message": "Captcha decryption failed"}), 500
            
        obj = json.loads(pt.decode())
        captcha_id = obj.get("id")
        img_b64 = obj.get("captcha") or ""
        
        if "," in img_b64:
            img_b64 = img_b64.split(",", 1)[1]
            
        return jsonify({
            "success": True, 
            "captchaId": captcha_id, 
            "captchaBase64": img_b64
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# API Route 3: Search Voter Data
@app.route('/search', methods=['POST'])
def search_api():
    try:
        req_data = request.get_json(silent=True) or request.form
        epic = req_data.get('epic', '')
        captcha_id = req_data.get('captchaId', '')
        captcha_text = req_data.get('captchaData', '')

        if not epic or not captcha_id or not captcha_text:
            return jsonify({"success": False, "message": "Missing required parameters (epic, captchaId, captchaData)"}), 400

        payload = {
            "epicNumber": epic.upper().strip(),
            "captchaId": captcha_id,
            "captchaData": captcha_text.strip(),
            "securityKey": "na",
        }
        
        body = encrypt_body(payload)
        
        r = requests.post(
            f"{BASE}/api/v1/elastic/search-by-epic-from-national-display-v1",
            headers=HEADERS,
            json=body,
            timeout=30,
        )
        
        if r.status_code != 200:
            return jsonify({"success": False, "message": "Invalid Captcha or Server Error"}), 400
            
        data = r.json()
        if isinstance(data, list) and data:
            return jsonify({"success": True, "data": data})
            
        return jsonify({"success": False, "message": "No records found or wrong captcha."})
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
