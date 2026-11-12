# Caso 5 — Scopes amplios / request sin `scope`

**Dónde está la falla:** configuración del **OP**.
**RFC:** [RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) (scope).

## Qué se ataca (en términos del estándar)

El parámetro `scope` acota qué permisos y qué datos pide el cliente. En este OP, si el cliente
**omite** el parámetro `scope`, se aplican **todos los scopes configurados** en el provider. Si el
provider tiene configurado un scope sensible, el token vuelve con esos datos aunque el cliente no
los haya pedido explícitamente.

## La mala configuración

El provider `caso5-insecure` tiene configurado, además de `openid`/`email`/`profile`, un scope
sensible `hr_data` que expone atributos del grupo de la víctima (`department`, `clearance`,
`salary_band`, `employee_id`). La ruta `/caso5/insecure` del RP pide **sin** `scope` → el token
vuelve con todos esos claims.

## La mitigación

- El cliente pide **scopes mínimos explícitos** (`scope=openid email`).
- El OP aplica una **policy de scope** por aplicación y no configura scopes sensibles donde no
  corresponden. El provider `caso5-secure` solo tiene `openid`/`email`.

La ruta `/caso5/secure` pide `scope=openid email` contra ese provider → el token trae solo lo
mínimo.

## Cómo correrlo

```bash
make case5          # abre http://localhost:8081/caso5/insecure
```

1. `http://localhost:8081/caso5/insecure`: el RP pide sin `scope`; el id_token vuelve con los
   claims sensibles **resaltados en rojo** y un aviso de fuga.
2. `http://localhost:8081/caso5/secure`: el RP pide `openid email`; el token trae solo lo mínimo.

## Qué observar

- **Inseguro:** `department`, `clearance`, `salary_band`, `employee_id` aparecen en el token.
- **Seguro:** ninguno de esos claims.

## Reset

```bash
make reset-case5
```

## Blueprint

[`blueprints/case5.yaml`](blueprints/case5.yaml) — scope mapping sensible `hr_data`,
`caso5-insecure` (lo incluye) y `caso5-secure` (mínimo).
