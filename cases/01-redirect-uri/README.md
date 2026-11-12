# Caso 1 — Robo del `code` por `redirect_uri` laxa

**Dónde está la falla:** configuración del **OP**.
**RFC:** [RFC 6749 §3.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2) ·
[RFC 9700 §2.1](https://www.rfc-editor.org/rfc/rfc9700) (exact string matching).

## Qué se ataca (en términos del estándar)

En el Authorization Code Flow, el OP devuelve el `code` redirigiendo el navegador a la
`redirect_uri`. El RFC 6749 exige que el OP **compare la `redirect_uri` por igualdad exacta
de strings** contra las URIs registradas para ese cliente. Si el OP afloja esa comparación —
por ejemplo validando con una **expresión regular mal escrita** — un atacante puede lograr que
una URI que *él* controla también matchee, y el OP le entrega el `code` de la víctima.

El `code` viaja por el navegador (paso 5 del flujo). Ahí es donde este caso ataca.

## La mala configuración

El provider `caso1-insecure` valida la `redirect_uri` con `matching_mode: regex` y este patrón:

```
http://localhost:808.\/callback
```

El punto `.` **sin escapar** matchea *cualquier* carácter. El RP legítimo escucha en
`http://localhost:8081/callback`, pero el patrón también matchea
`http://localhost:8082/callback` — el puerto del **atacante**. El OP, al validar, da por buena
la URI del atacante y le manda el `code`.

> En un escenario con dominios reales el equivalente es registrar `https://rp.lab.com/cb` como
> regex: el `.` matchea `rpXlab`, y el atacante registra `rpYlab.com` para quedarse con el `code`.
> Aquí usamos puertos de `localhost` en vez de dominios para no depender de DNS; la falla del
> estándar es la misma.

## La mitigación

El provider `caso1-secure` usa `matching_mode: strict` con la URL literal exacta:

```
http://localhost:8081/callback
```

Una `redirect_uri` literal por entorno, comparada como string exacto. El intento hacia `8082`
es rechazado por el OP.

## Cómo correrlo

```bash
make case1          # abre http://localhost:8081/caso1/insecure
```

1. Asegurate de tener sesión de **víctima** en el OP (abrí `http://localhost:9000` y logueate
   con `victima` / `Kavacon2026!`). Así el clic del atacante no pide login y el robo es directo.
2. En `http://localhost:8081/caso1/insecure`, hacé clic en **"Seguir el link del atacante →"**.
3. Mirá el servidor del atacante en `http://localhost:8082/`: el `code` quedó capturado ahí.
4. Repetí en `http://localhost:8081/caso1/secure`: el mismo intento ahora falla, el OP
   rechaza la `redirect_uri` del atacante.

## Qué observar

- **Inseguro:** el OP redirige a `:8082` con `?code=...` → aparece en el log del atacante.
- **Seguro:** el OP muestra un error de `redirect_uri` inválida y **no** emite `code`.
- El `code` es de un solo uso y este cliente es confidencial (hace falta el `client_secret`
  para canjearlo), pero **que el `code` llegue al atacante ya es la falla**: el canal de
  redirección nunca debió entregarlo a una URI no registrada.

## Reset

```bash
make reset-case1    # limpia capturas del atacante y sesión del RP
```

## Blueprint

[`blueprints/case1.yaml`](blueprints/case1.yaml) — define `caso1-insecure` (regex) y
`caso1-secure` (strict), coexistiendo.
