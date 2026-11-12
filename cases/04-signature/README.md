# Caso 4 — Firma del token y confusión de algoritmo

**RFC:** [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) /
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) (JWS/JWT) ·
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) (JWT BCP).

Son dos sub-casos separados.

## 4a — Firma simétrica vs asimétrica (config del OP)

- `caso4a-hs256`: **sin** `signing_key` → el OP firma el `id_token` con **HS256** usando el
  `client_secret` (clave **simétrica compartida**). El JWKS queda vacío.
- `caso4a-rs256`: **con** `signing_key` → **RS256**, verificable por JWKS (clave **pública**).

**Por qué el secreto compartido es peor:** con HS256 la clave de firma *es* el `client_secret`,
que el RP también tiene; cualquiera que lo conozca puede fabricar tokens. Con RS256 el OP firma con
su clave privada y el RP solo verifica con la pública: un secreto filtrado del RP no alcanza para
falsificar.

Abrí `http://localhost:8081/caso4a`: muestra ambos `id_token` reales decodificados, con el `alg`
resaltado.

## 4b — Confusión de algoritmo (la falla real, en el cliente)

El provider `caso4b` firma con **RS256**. La falla es del **RP**: elegir cómo verificar según el
`alg` del propio token.

```
alg = header["alg"]
if alg == "RS256": verificar con la clave publica (RSA)
if alg == "HS256": usar la clave PUBLICA del JWKS como secreto HMAC   # &larr; el bug
```

La clave pública está en el JWKS: es **conocida**. El atacante falsifica un `id_token` con privilegios
de admin, lo firma **HS256** con esa misma clave pública como secreto, y el RP inseguro —que eligió
HMAC por el header— lo da por válido. Escalada. (A falsificar un token así se lo conoce en inglés
como *token forging* — "forjar" un token.)

**Mitigación:** `jwt.decode(token, clave_publica, algorithms=["RS256"])` — algoritmo **fijo**, nunca
confiar en el header.

### Cómo correrlo

```bash
make case4          # abre http://localhost:8081/caso4b/insecure
```

1. En `http://localhost:8081/caso4b/insecure`:
   - **"Verificar un token legítimo"** → pasa (RS256). La verificación insegura no está rota para
     el uso normal.
   - **"Abrir el falsificador del atacante"** → el atacante arma un token HS256 de admin → **"Enviar al
     RP"** → el RP lo **acepta como `akadmin@lab.local`** (banner de escalada).
2. En `http://localhost:8081/caso4b/secure`: el mismo token falsificado es **rechazado**
   (alg no permitido).

### Qué observar

- El decodificador resalta el `alg`: `RS256` en el legítimo, `HS256` en el falsificado.
- Inseguro: acepta el HS256 falsificado → admin. Seguro: lo rechaza.

## Reset

```bash
make reset-case4
```

## Blueprint

[`blueprints/case4.yaml`](blueprints/case4.yaml) — `caso4a-hs256` (sin signing_key),
`caso4a-rs256` y `caso4b` (RS256 + JWKS).
