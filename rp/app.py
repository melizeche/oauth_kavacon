"""
RP (Relying Party) del laboratorio OAuth 2.0 / OIDC — Kavacon 2026.

Un unico servicio Flask sirve TODOS los casos a la vez, una ruta por caso y
variante (/casoN/insecure, /casoN/secure), cada una cableada a su client_id.
Cambiar de caso = abrir una URL. No se reinicia nada.

Este cliente esta programado para ser configurable e INSEGURO a proposito
(segun el caso). No es un ejemplo de como escribir un cliente OIDC real.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse

import jwt
import requests
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jwt import PyJWK
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

OP_BROWSER_URL = os.environ.get("OP_BROWSER_URL", "http://localhost:9000").rstrip("/")
OP_INTERNAL_URL = os.environ.get("OP_INTERNAL_URL", "http://localhost:9000").rstrip("/")
RP_BASE_URL = os.environ.get("RP_BASE_URL", "http://localhost:8081").rstrip("/")
ATTACKER_URL = os.environ.get("ATTACKER_URL", "http://localhost:8082").rstrip("/")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-insecure")


# ---------------------------------------------------------------------------
# Registro de casos (para el indice y los casos 1 y 2). El caso 3 usa rutas
# dedicadas mas abajo.
# ---------------------------------------------------------------------------
def case(client_id, client_secret, app_slug, **flags):
    cfg = {
        "client_id": client_id,
        "client_secret": client_secret,
        "app_slug": app_slug,
        "use_state": True,
        "use_nonce": True,
        "use_pkce": True,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_path": "/callback",
    }
    cfg.update(flags)
    return cfg


CASES = {
    ("caso1", "insecure"): case(
        "caso1-insecure", "caso1-insecure-secret-no-usar-en-prod", "caso1-insecure"
    ),
    ("caso1", "secure"): case(
        "caso1-secure", "caso1-secure-secret-no-usar-en-prod", "caso1-secure"
    ),
    ("caso2", "insecure"): case(
        "caso2-insecure",
        "caso2-insecure-secret-no-usar-en-prod",
        "caso2-insecure",
        response_type="id_token token",
        use_pkce=False,
        redirect_path="/implicit-callback",
    ),
    ("caso2", "secure"): case(
        "caso2-secure", "caso2-secure-secret-no-usar-en-prod", "caso2-secure"
    ),
    # Caso 3 — falla en el RP. Se registran para el indice; las rutas son
    # dedicadas (ver mas abajo).
    ("caso3", "insecure"): case(
        "caso3-insecure",
        "caso3-insecure-secret-no-usar-en-prod",
        "caso3-insecure",
        use_state=False,
        use_nonce=False,
        use_pkce=False,
        redirect_path="/caso3/insecure/callback",
    ),
    ("caso3", "secure"): case(
        "caso3-secure",
        "caso3-secure-secret-no-usar-en-prod",
        "caso3-secure",
        redirect_path="/caso3/secure/callback",
    ),
}

CASE_META = {
    "caso1": {
        "title": "Caso 1 — redirect_uri laxa (config del OP)",
        "rfc": "RFC 6749 §3.1.2 · RFC 9700 §2.1 (exact string matching)",
        "template": "case1.html",
    },
    "caso2": {
        "title": "Caso 2 — flujos legacy habilitados (config del OP)",
        "rfc": "RFC 9700 §2.1.2 (no implicit) · OpenID Connect Core (hybrid)",
        "template": "case2.html",
    },
    "caso3": {
        "title": "Caso 3 — sin state / nonce / PKCE (en el RP)",
        "rfc": "RFC 6749 §10.12 · RFC 7636 (PKCE) · OpenID Connect Core (nonce)",
        "template": "case3.html",
    },
    "caso4": {
        "title": "Caso 4 — firma y confusión de algoritmo",
        "rfc": "RFC 7515 / 7519 · RFC 8725 (JWT BCP)",
        "links": [
            {"label": "4a · HS256 vs RS256", "url": "/caso4a", "kind": "info"},
            {"label": "4b · confusión (INSEGURO)", "url": "/caso4b/insecure", "kind": "bad"},
            {"label": "4b · confusión (SEGURO)", "url": "/caso4b/secure", "kind": "ok"},
        ],
    },
    "caso5": {
        "title": "Caso 5 — scopes amplios / request sin scope (config del OP)",
        "rfc": "RFC 6749 §3.3 (scope)",
        "links": [
            {"label": "INSEGURO (sin scope)", "url": "/caso5/insecure", "kind": "bad"},
            {"label": "SEGURO (scope mínimo)", "url": "/caso5/secure", "kind": "ok"},
        ],
    },
    "caso6": {
        "title": "Caso 6 — mix-up: el cliente no valida el issuer (en el RP)",
        "rfc": "RFC 9207 · RFC 9700 §4.4 (mix-up)",
        "links": [
            {"label": "INSEGURO (no valida iss)", "url": "/caso6/insecure", "kind": "bad"},
            {"label": "SEGURO (valida iss)", "url": "/caso6/secure", "kind": "ok"},
        ],
    },
}

VICTIMA_PASSWORD = "Kavacon2026!"


# ---------------------------------------------------------------------------
# Helpers OIDC
# ---------------------------------------------------------------------------
def op_authorize_browser():
    return f"{OP_BROWSER_URL}/application/o/authorize/"


def op_token_internal():
    return f"{OP_INTERNAL_URL}/application/o/token/"


def op_jwks_internal(slug):
    return f"{OP_INTERNAL_URL}/application/o/{slug}/jwks/"


def op_issuer_expected(slug):
    return f"{OP_INTERNAL_URL}/application/o/{slug}/"


def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    return verifier, challenge


def build_authorize_url(cfg, redirect_uri, state=None, nonce=None, code_challenge=None):
    params = {
        "client_id": cfg["client_id"],
        "response_type": cfg["response_type"],
        "redirect_uri": redirect_uri,
        "scope": cfg["scope"],
    }
    if state:
        params["state"] = state
    if nonce:
        params["nonce"] = nonce
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return op_authorize_browser() + "?" + urllib.parse.urlencode(params)


def redeem_code(client_id, client_secret, code, redirect_uri, code_verifier=None):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    return requests.post(op_token_internal(), data=data, timeout=10)


def verify_id_token(id_token, slug, client_id, expected_nonce=None):
    jwks = jwt.PyJWKClient(op_jwks_internal(slug))
    signing_key = jwks.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=op_issuer_expected(slug),
    )
    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        raise ValueError("nonce no coincide: posible replay de id_token")
    return claims


# ---------------------------------------------------------------------------
# Helpers del Caso 4 (firma / confusion de algoritmo)
# ---------------------------------------------------------------------------
def _b64url_json(segment):
    pad = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def decode_jwt_parts(token):
    h, p, _ = token.split(".")
    return _b64url_json(h), _b64url_json(p)


def jwks_public_pem(slug):
    """PEM de la clave publica del OP (bytes). RP y atacante derivan el mismo."""
    data = requests.get(op_jwks_internal(slug), timeout=10).json()
    key = PyJWK.from_dict(data["keys"][0]).key
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def fetch_id_token(username, password, client_id, client_secret, slug, redirect,
                   scope="openid email profile"):
    """Obtiene un id_token real del OP (login + code + canje), server-side.
    Si scope es falsy, se omite el parametro: el OP aplica TODOS los configurados."""
    s = requests.Session()
    h = {"Accept": "application/json"}
    ex = f"{OP_INTERNAL_URL}/api/v3/flows/executor/default-authentication-flow/"
    s.get(ex, headers=h, timeout=10)
    s.post(ex, json={"uid_field": username}, headers=h, timeout=10)
    r = s.post(ex, json={"password": password}, headers=h, timeout=10)
    if r.json().get("component") != "xak-flow-redirect":
        raise RuntimeError("login fallido")
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect,
        "state": "s",
    }
    if scope:
        params["scope"] = scope
    r = s.get(
        f"{OP_INTERNAL_URL}/application/o/authorize/?" + urllib.parse.urlencode(params),
        allow_redirects=False,
        timeout=10,
    )
    path = urllib.parse.urlparse(redirect).path
    loc = r.headers.get("Location", "")
    hops = 0
    while r.status_code in (301, 302) and path not in loc and hops < 6:
        nxt = loc if loc.startswith("http") else OP_INTERNAL_URL + loc
        r = s.get(nxt, allow_redirects=False, timeout=10)
        loc = r.headers.get("Location", "")
        hops += 1
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
    if not code:
        raise RuntimeError("no se obtuvo code")
    tr = redeem_code(client_id, client_secret, code, redirect)
    if tr.status_code != 200:
        raise RuntimeError(f"token endpoint {tr.status_code}: {tr.text}")
    return tr.json().get("id_token")


def verify_insecure(token, slug, client_id):
    """Verificacion DELIBERADAMENTE INSEGURA: elige el algoritmo segun el header
    del token. Si dice HS256, usa la clave PUBLICA del JWKS como secreto HMAC."""
    header, payload = decode_jwt_parts(token)
    alg = header.get("alg")
    signing_input, _, sig_b64 = token.rpartition(".")
    if alg == "RS256":
        key = PyJWK.from_dict(requests.get(op_jwks_internal(slug), timeout=10).json()["keys"][0]).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=client_id, issuer=op_issuer_expected(slug)
        )
        return claims, "firma RS256 verificada con JWKS", True
    if alg == "HS256":
        pem = jwks_public_pem(slug)  # BUG: la clave publica como secreto
        expected = (
            base64.urlsafe_b64encode(
                hmac.new(pem, signing_input.encode(), hashlib.sha256).digest()
            )
            .decode()
            .rstrip("=")
        )
        if hmac.compare_digest(expected, sig_b64):
            if payload.get("aud") != client_id:
                return payload, "aud invalida", False
            if payload.get("iss") != op_issuer_expected(slug):
                return payload, "iss invalida", False
            if payload.get("exp", 0) < time.time():
                return payload, "expirado", False
            return payload, "firma HS256 'OK' usando la clave publica — FALSIFICADO ACEPTADO", True
        return payload, "firma HS256 invalida", False
    return payload, f"alg no soportado: {alg}", False


def verify_secure(token, slug, client_id):
    """Verificacion correcta: algorithms=['RS256'] fijo. Nunca confia en el header."""
    try:
        jwks = jwt.PyJWKClient(op_jwks_internal(slug))
        key = jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=client_id, issuer=op_issuer_expected(slug)
        )
        return claims, "firma RS256 verificada (algorithms fijo)", True
    except Exception as exc:  # noqa: BLE001
        return None, f"RECHAZADO: {exc}", False


# ---------------------------------------------------------------------------
# Indice
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    cases = []
    for name, meta in CASE_META.items():
        if meta.get("links"):
            links = meta["links"]
        else:
            links = []
            for v in sorted({v for (c, v) in CASES if c == name}, reverse=True):
                links.append(
                    {
                        "label": "INSEGURO" if v == "insecure" else "SEGURO",
                        "url": f"/{name}/{v}",
                        "kind": "bad" if v == "insecure" else "ok",
                    }
                )
        cases.append({"name": name, "links": links, **meta})
    return render_template("index.html", cases=cases)


@app.route("/caso1/<variant>")
@app.route("/caso2/<variant>")
def case_page(variant):
    case_name = request.path.split("/")[1]
    cfg = CASES.get((case_name, variant))
    if not cfg:
        return "Caso o variante desconocida", 404
    meta = CASE_META.get(case_name, {})
    login_url = url_for("login", case_name=case_name, variant=variant)

    if case_name == "caso1":
        attacker_redirect = f"{ATTACKER_URL}/callback"
        attacker_link = build_authorize_url(
            cfg, attacker_redirect, state="estado-victima-123", nonce="n-victima"
        )
        return render_template(
            "case1.html",
            variant=variant,
            meta=meta,
            login_url=login_url,
            redirect_uri_legit=f"{RP_BASE_URL}/callback",
            attacker_redirect=attacker_redirect,
            attacker_link=attacker_link,
        )

    return render_template(
        "case2.html",
        variant=variant,
        meta=meta,
        login_url=login_url,
        response_type=cfg["response_type"],
        redirect_uri=f"{RP_BASE_URL}{cfg['redirect_path']}",
        attacker_url=ATTACKER_URL,
    )


# ---------------------------------------------------------------------------
# Login y callback genericos (casos 1 y 2)
# ---------------------------------------------------------------------------
@app.route("/<case_name>/<variant>/login")
def login(case_name, variant):
    cfg = CASES.get((case_name, variant))
    if not cfg:
        return "Caso o variante desconocida", 404
    state = secrets.token_urlsafe(16) if cfg["use_state"] else None
    nonce = secrets.token_urlsafe(16) if cfg["use_nonce"] else None
    redirect_uri = f"{RP_BASE_URL}{cfg['redirect_path']}"
    session["oauth"] = {
        "case": case_name,
        "variant": variant,
        "state": state,
        "nonce": nonce,
        "redirect_uri": redirect_uri,
    }
    return redirect(build_authorize_url(cfg, redirect_uri, state=state, nonce=nonce))


@app.route("/callback")
def callback():
    pending = session.get("oauth")
    if not pending:
        return render_template("error.html", msg="No hay login pendiente en la sesion.")
    cfg = CASES.get((pending["case"], pending["variant"]))
    if request.args.get("error"):
        return render_template(
            "error.html",
            msg=f"El OP devolvio un error: {request.args.get('error')} — "
            f"{request.args.get('error_description', '')}",
        )
    if cfg["use_state"] and request.args.get("state") != pending["state"]:
        return render_template("error.html", msg="state no coincide: posible CSRF.")
    code = request.args.get("code")
    if not code:
        return render_template("error.html", msg="No llego 'code' en el callback.")

    tr = redeem_code(cfg["client_id"], cfg["client_secret"], code, pending["redirect_uri"])
    if tr.status_code != 200:
        return render_template("error.html", msg=f"Token endpoint {tr.status_code}: {tr.text}")
    tokens = tr.json()
    claims, verify_error = None, None
    if tokens.get("id_token"):
        try:
            claims = verify_id_token(
                tokens["id_token"],
                cfg["app_slug"],
                cfg["client_id"],
                pending["nonce"] if cfg["use_nonce"] else None,
            )
        except Exception as exc:  # noqa: BLE001
            verify_error = f"Fallo la verificacion del id_token: {exc}"
    return render_template(
        "success.html",
        case=pending["case"],
        variant=pending["variant"],
        claims=claims,
        verify_error=verify_error,
        tokens={k: v for k, v in tokens.items() if k != "id_token"},
        id_token=tokens.get("id_token"),
    )


@app.route("/implicit-callback")
def implicit_callback():
    """Callback del flujo IMPLICIT (Caso 2): el token vuelve en el #fragment."""
    return render_template("implicit_callback.html", attacker_url=ATTACKER_URL)


# ---------------------------------------------------------------------------
# Caso 3 — state / nonce / PKCE (rutas dedicadas, falla en el RP)
# ---------------------------------------------------------------------------
CASO3 = {
    "insecure": {
        "client_id": "caso3-insecure",
        "client_secret": "caso3-insecure-secret-no-usar-en-prod",
        "slug": "caso3-insecure",
        "redirect": f"{RP_BASE_URL}/caso3/insecure/callback",
    },
    "secure": {
        "client_id": "caso3-secure",
        "client_secret": "caso3-secure-secret-no-usar-en-prod",
        "slug": "caso3-secure",
        "redirect": f"{RP_BASE_URL}/caso3/secure/callback",
    },
}


@app.route("/caso3/<variant>")
def caso3_page(variant):
    if variant not in CASO3:
        return "Variante desconocida", 404
    return render_template(
        "case3.html",
        variant=variant,
        meta=CASE_META["caso3"],
        login_url=url_for("caso3_login", variant=variant),
        attacker_csrf_url=f"{ATTACKER_URL}/caso3/csrf",
    )


@app.route("/caso3/<variant>/login")
def caso3_login(variant):
    c = CASO3.get(variant)
    if not c:
        return "Variante desconocida", 404
    if variant == "insecure":
        # El RP NO genera state ni nonce ni PKCE. Vulnerable.
        cfg = {"client_id": c["client_id"], "response_type": "code", "scope": "openid email profile"}
        return redirect(build_authorize_url(cfg, c["redirect"]))
    # Seguro: state + nonce + PKCE S256.
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    verifier, challenge = pkce_pair()
    session["caso3"] = {"state": state, "nonce": nonce, "verifier": verifier}
    cfg = {"client_id": c["client_id"], "response_type": "code", "scope": "openid email profile"}
    return redirect(
        build_authorize_url(cfg, c["redirect"], state=state, nonce=nonce, code_challenge=challenge)
    )


@app.route("/caso3/insecure/callback")
def caso3_insecure_callback():
    """Callback INSEGURO: canjea cualquier code que llegue, sin validar state,
    nonce ni PKCE. Aca aterriza el login-CSRF: el code es del ATACANTE."""
    if request.args.get("error"):
        return render_template("error.html", msg=f"OP error: {request.args.get('error')}")
    code = request.args.get("code")
    if not code:
        return render_template("error.html", msg="No llego 'code'.")
    c = CASO3["insecure"]
    tr = redeem_code(c["client_id"], c["client_secret"], code, c["redirect"])
    if tr.status_code != 200:
        return render_template("error.html", msg=f"Token endpoint {tr.status_code}: {tr.text}")
    tokens = tr.json()
    identity = None
    if tokens.get("id_token"):
        try:
            identity = verify_id_token(tokens["id_token"], c["slug"], c["client_id"])
        except Exception as exc:  # noqa: BLE001
            identity = {"error": str(exc)}
    return render_template("case3_session.html", variant="insecure", identity=identity, validated=False)


@app.route("/caso3/secure/callback")
def caso3_secure_callback():
    """Callback SEGURO: exige pending con state/nonce/verifier y los valida."""
    pending = session.get("caso3")
    if not pending:
        return render_template(
            "error.html",
            msg="No hay login pendiente (state desconocido): se rechaza. "
            "Asi se corta el login-CSRF.",
        )
    if request.args.get("state") != pending["state"]:
        return render_template("error.html", msg="state no coincide: se rechaza (CSRF).")
    code = request.args.get("code")
    if not code:
        return render_template("error.html", msg="No llego 'code'.")
    c = CASO3["secure"]
    tr = redeem_code(c["client_id"], c["client_secret"], code, c["redirect"], pending["verifier"])
    if tr.status_code != 200:
        return render_template(
            "error.html",
            msg=f"Token endpoint {tr.status_code} (PKCE/code invalido): {tr.text}",
        )
    tokens = tr.json()
    identity, verify_error = None, None
    if tokens.get("id_token"):
        try:
            identity = verify_id_token(tokens["id_token"], c["slug"], c["client_id"], pending["nonce"])
        except Exception as exc:  # noqa: BLE001
            verify_error = str(exc)
    session.pop("caso3", None)
    return render_template(
        "case3_session.html",
        variant="secure",
        identity=identity,
        validated=True,
        verify_error=verify_error,
    )


# ---------------------------------------------------------------------------
# Caso 4 — firma / confusion de algoritmo
# ---------------------------------------------------------------------------
@app.route("/caso4a")
def caso4a():
    specs = [
        ("caso4a-hs256", "caso4a-hs256-secret-no-usar-en-prod", "HS256",
         "Firmado con el client_secret (clave simétrica compartida). JWKS vacío."),
        ("caso4a-rs256", "caso4a-rs256-secret-no-usar-en-prod", "RS256",
         "Firmado con la clave privada del OP. Verificable por JWKS (clave pública)."),
    ]
    tokens = []
    for cid, sec, alg, note in specs:
        try:
            t = fetch_id_token("victima", VICTIMA_PASSWORD, cid, sec, cid,
                               f"{RP_BASE_URL}/caso4a/callback")
            header, payload = decode_jwt_parts(t)
            tokens.append({"cid": cid, "alg": alg, "note": note,
                           "header": header, "payload": payload, "raw": t, "error": None})
        except Exception as exc:  # noqa: BLE001
            tokens.append({"cid": cid, "alg": alg, "note": note, "error": str(exc)})
    return render_template("case4a.html", meta=CASE_META["caso4"], tokens=tokens)


@app.route("/caso4b/<variant>")
def caso4b_page(variant):
    if variant not in ("insecure", "secure"):
        return "Variante desconocida", 404
    return render_template(
        "case4b.html",
        variant=variant,
        meta=CASE_META["caso4"],
        forge_url=f"{ATTACKER_URL}/caso4b/forge?variant={variant}",
        legit_url=url_for("caso4b_verify", variant=variant) + "?mode=legit",
    )


@app.route("/caso4b/<variant>/verify")
def caso4b_verify(variant):
    if variant not in ("insecure", "secure"):
        return "Variante desconocida", 404
    slug = client_id = "caso4b"
    if request.args.get("mode") == "legit":
        try:
            token = fetch_id_token("victima", VICTIMA_PASSWORD, "caso4b",
                                   "caso4b-secret-no-usar-en-prod", slug,
                                   f"{RP_BASE_URL}/caso4b/callback")
        except Exception as exc:  # noqa: BLE001
            return render_template("error.html", msg=f"No se pudo obtener token legitimo: {exc}")
        source = "token legítimo del OP (RS256)"
    else:
        token = request.args.get("id_token")
        source = "token recibido (inyectado por el atacante)"
    if not token:
        return render_template("error.html", msg="Falta id_token.")
    header, payload = decode_jwt_parts(token)
    if variant == "insecure":
        claims, verdict, ok = verify_insecure(token, slug, client_id)
    else:
        claims, verdict, ok = verify_secure(token, slug, client_id)
    who = (claims or payload).get("email")
    alg = header.get("alg")
    if ok:
        flag = " [TOKEN FALSIFICADO ACEPTADO — ESCALADA]" if alg == "HS256" else ""
        print(f"[RP] caso4b/{variant}: autenticado como {who} (alg={alg}){flag}", flush=True)
    else:
        print(f"[RP] caso4b/{variant}: token RECHAZADO ({verdict})", flush=True)
    return render_template(
        "case4b_verify.html",
        variant=variant,
        source=source,
        header=header,
        payload=claims or payload,
        verdict=verdict,
        ok=ok,
        raw=token,
    )


# ---------------------------------------------------------------------------
# Caso 5 — scopes amplios / request sin scope
# ---------------------------------------------------------------------------
SENSITIVE_CLAIMS = {"department", "clearance", "salary_band", "employee_id"}


@app.route("/caso5/<variant>")
def caso5_page(variant):
    if variant not in ("insecure", "secure"):
        return "Variante desconocida", 404
    if variant == "insecure":
        client_id = "caso5-insecure"
        secret = "caso5-insecure-secret-no-usar-en-prod"
        scope = None  # SIN scope: el OP aplica todos los configurados
        requested = "(sin parámetro scope)"
    else:
        client_id = "caso5-secure"
        secret = "caso5-secure-secret-no-usar-en-prod"
        scope = "openid email"
        requested = "openid email"
    try:
        token = fetch_id_token("victima", VICTIMA_PASSWORD, client_id, secret, client_id,
                               f"{RP_BASE_URL}/caso5/callback", scope=scope)
        header, payload = decode_jwt_parts(token)
    except Exception as exc:  # noqa: BLE001
        return render_template("error.html", msg=f"No se pudo obtener token: {exc}")
    leaked = sorted(SENSITIVE_CLAIMS & set(payload.keys()))
    return render_template(
        "case5.html",
        variant=variant,
        meta=CASE_META["caso5"],
        requested=requested,
        header=header,
        payload=payload,
        sensitive=SENSITIVE_CLAIMS,
        leaked=leaked,
        raw=token,
    )


# ---------------------------------------------------------------------------
# Caso 6 — mix-up / issuer
# ---------------------------------------------------------------------------
# El RP esta federado con dos OPs: acepta como aud cualquiera de sus client_ids.
CASO6_AUDIENCES = ["caso6-corp", "caso6-evil"]
CASO6_CORP_ISSUER = op_issuer_expected("caso6-corp")


def verify_mixup(token, check_issuer):
    """Verifica el id_token. Ambos OPs firman con la misma clave, asi que la
    firma es valida para los dos. Lo unico que distingue el origen es `iss`.
    Si check_issuer es False (RP inseguro) no se valida el issuer."""
    key = PyJWK.from_dict(
        requests.get(op_jwks_internal("caso6-corp"), timeout=10).json()["keys"][0]
    ).key
    kwargs = {"algorithms": ["RS256"], "audience": CASO6_AUDIENCES}
    if check_issuer:
        kwargs["issuer"] = CASO6_CORP_ISSUER
    claims = jwt.decode(token, key, **kwargs)
    return claims


@app.route("/caso6/<variant>")
def caso6_page(variant):
    if variant not in ("insecure", "secure"):
        return "Variante desconocida", 404
    return render_template(
        "case6.html",
        variant=variant,
        meta=CASE_META["caso6"],
        legit_url=url_for("caso6_verify", variant=variant) + "?mode=legit",
        mixup_url=f"{ATTACKER_URL}/caso6/mixup?variant={variant}",
        corp_issuer=CASO6_CORP_ISSUER,
    )


@app.route("/caso6/<variant>/verify")
def caso6_verify(variant):
    if variant not in ("insecure", "secure"):
        return "Variante desconocida", 404
    if request.args.get("mode") == "legit":
        try:
            token = fetch_id_token("victima", VICTIMA_PASSWORD, "caso6-corp",
                                   "caso6-corp-secret-no-usar-en-prod", "caso6-corp",
                                   f"{RP_BASE_URL}/caso6/corp-callback")
        except Exception as exc:  # noqa: BLE001
            return render_template("error.html", msg=f"No se pudo obtener token corp: {exc}")
        source = "login corporativo legítimo (OP-Corp)"
    else:
        token = request.args.get("id_token")
        source = "id_token recibido (inyectado por el atacante)"
    if not token:
        return render_template("error.html", msg="Falta id_token.")
    header, payload = decode_jwt_parts(token)
    try:
        claims = verify_mixup(token, check_issuer=(variant == "secure"))
        ok, verdict = True, ("iss validado contra OP-Corp" if variant == "secure"
                             else "firma + aud OK (iss NO validado)")
    except Exception as exc:  # noqa: BLE001
        claims, ok, verdict = None, False, f"RECHAZADO: {exc}"
    iss = payload.get("iss", "")
    from_evil = iss.endswith("/caso6-evil/")
    who = (claims or payload).get("email")
    if ok:
        flag = " [TOKEN DE OP-EVIL ACEPTADO — MIX-UP]" if from_evil else ""
        print(f"[RP] caso6/{variant}: acceso al panel como {who} (iss={iss}){flag}", flush=True)
    else:
        print(f"[RP] caso6/{variant}: RECHAZADO ({verdict})", flush=True)
    return render_template(
        "case6_verify.html",
        variant=variant,
        source=source,
        header=header,
        payload=claims or payload,
        verdict=verdict,
        ok=ok,
        from_evil=from_evil,
        raw=token,
    )


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
