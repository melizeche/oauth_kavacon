# Caso 2 — Flujos legacy habilitados (implicit / hybrid)

**Dónde está la falla:** configuración del **OP**.
**RFC:** [RFC 9700 §2.1.2](https://www.rfc-editor.org/rfc/rfc9700) (no usar implicit) ·
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) (hybrid).

## Qué se ataca (en términos del estándar)

El **implicit flow** (y el **hybrid**) devuelven tokens directamente en el **`#fragment`** de la
`redirect_uri`, sin canje server-to-server. Un token en el fragment queda expuesto: en el
historial del navegador, y a **cualquier script que corra en la página** del callback (widgets de
analytics, ads, librerías de terceros). RFC 9700 recomienda **no usar implicit**: solo
authorization code (con PKCE), donde el token viaja por un canal server-to-server y nunca aparece
en la URL.

> **Nota sobre `response_type`:** en este OP el implicit es `id_token` o `id_token token`; no
> existe un `token` a secas. El RP del lab usa `response_type=id_token token`.

## La mala configuración

El provider `caso2-insecure` habilita grants legacy:

```yaml
grant_types: [authorization_code, implicit, hybrid, refresh_token]
```

El RP pide `response_type=id_token token`. El OP responde redirigiendo a:

```
http://localhost:8081/implicit-callback#access_token=ey...&id_token=ey...&token_type=bearer&...
```

El token está en el fragment. La página de callback carga un "widget de tercero" servido por el
atacante (`http://localhost:8082/steal.js`) que corre en el contexto de la página, lee
`window.location.hash` y exfiltra el token. Es exactamente cómo un script embebido roba tokens de
implicit.

## La mitigación

El provider `caso2-secure` habilita solo:

```yaml
grant_types: [authorization_code, refresh_token]
```

El RP usa `response_type=code` + PKCE. El token se canjea en `/callback` server-to-server y
**nunca** aparece en la URL. El widget del atacante no encuentra nada en el fragment.

## Cómo correrlo

```bash
make case2          # abre http://localhost:8081/caso2/insecure
```

1. Tené sesión de **víctima** en el OP (`http://localhost:9000`, `victima` / `Kavacon2026!`).
2. En `http://localhost:8081/caso2/insecure`, **"Login como la víctima (implicit)"**.
3. En el callback, mirá la **barra de direcciones**: el token está en el `#fragment`.
4. Abrí `http://localhost:8082/`: el `access_token` quedó capturado (lo robó `steal.js`).
5. Compará con `http://localhost:8081/caso2/secure`: code flow, nada en la URL, nada capturado.

## Qué observar

- **Inseguro:** token visible en la URL (`#access_token=...`) → el widget de tercero lo exfiltra
  al atacante, que lo muestra en grande.
- **Seguro:** la URL del callback no lleva token; el atacante no captura nada.
- El punto es que **implicit entrega el token a la página**, no a un canal protegido.

## Reset

```bash
make reset-case2    # limpia capturas del atacante y sesión del RP
```

## Blueprint

[`blueprints/case2.yaml`](blueprints/case2.yaml) — `caso2-insecure` (implicit+hybrid) y
`caso2-secure` (solo code), coexistiendo.
