# Caso 3 — Falta de `state` / `nonce` / PKCE (en el cliente)

**Dónde está la falla:** el **cliente (RP)**. El OP está bien configurado.
**RFC:** [RFC 6749 §10.12](https://www.rfc-editor.org/rfc/rfc6749#section-10.12) (CSRF / state) ·
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) (PKCE) ·
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) (nonce).

## Qué se ataca (en términos del estándar)

`state`, `nonce` y PKCE son responsabilidad del **cliente**: ningún IdP los genera ni los valida
por vos. Si el RP los omite:

- **sin `state` → login CSRF (RFC 6749 §10.12):** el atacante hace que tu navegador complete el
  callback con **su** `code`. Tu sesión del RP queda logueada como el atacante.
- **sin `nonce` → replay de `id_token` (OIDC Core):** un `id_token` viejo se reinyecta sin que el
  RP lo detecte.
- **sin PKCE → inyección de code (RFC 7636):** un `code` interceptado se canjea desde otro
  contexto; con PKCE el code queda ligado al `code_verifier` de quien lo pidió.

## La demo en vivo: login-CSRF

El RP inseguro (`/caso3/insecure/*`) **no** genera ni valida `state`, `nonce` ni PKCE. Su callback
canjea cualquier `code` que llegue.

1. Abrí `http://localhost:8081/caso3/insecure` → **"Abrir la trampa del atacante"**.
2. La trampa (`http://localhost:8082/caso3/csrf`) se loguea como `atacante@lab.local`, consigue un
   `code` para esa cuenta (sin canjearlo) y arma un botón **"Continuar"**.
3. Hacés clic como lo haría la víctima → caés en `http://localhost:8081/caso3/insecure/callback`
   con el `code` del atacante.
4. El RP lo canjea y muestra **"sesión iniciada como `atacante@lab.local`"**. Tu sesión del RP es
   ahora la cuenta del atacante: lo que subas o guardes queda en su poder.

## La mitigación

El RP seguro (`/caso3/secure/*`) genera y valida:

- **`state`:** el callback exige que la respuesta corresponda a un login que *vos* iniciaste.
- **`nonce`:** se valida contra el `id_token`, cortando el replay.
- **PKCE S256:** `code_challenge` en el `/authorize` y `code_verifier` en el canje.

Probá `http://localhost:8081/caso3/secure` → **"Probar la trampa del atacante"**: el callback
seguro rechaza el `code` inyectado porque su `state` no coincide con ninguna sesión tuya.

## Qué observar

- **Inseguro:** la página final dice `atacante@lab.local` — un login que no iniciaste.
- **Seguro:** error de `state` (se rechaza). El ataque no prospera.
- En el `/authorize` seguro, en la URL aparece `code_challenge=...&code_challenge_method=S256`
  (PKCE) y `nonce=...`; en el inseguro no.

## Reset

```bash
make reset-case3
```

## Blueprint

[`blueprints/case3.yaml`](blueprints/case3.yaml) — providers `caso3-insecure` / `caso3-secure`
(ambos code flow correctos) y el usuario `atacante`. La diferencia vive en el RP.
