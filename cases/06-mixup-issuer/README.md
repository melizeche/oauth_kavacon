# Caso 6 — Mix-up: el cliente no valida el `issuer`

**Dónde está la falla:** el **cliente (RP)**.
**RFC:** [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) (parámetro `iss`) ·
[RFC 9700 §4.4](https://www.rfc-editor.org/rfc/rfc9700) (mix-up).

## Qué se ataca (en términos del estándar)

Cuando un cliente trabaja con **más de un OP**, tiene que saber de cuál vino cada respuesta. Si no
lo verifica, un atacante puede **mezclar** respuestas entre proveedores: hacer que el cliente
acepte, en un contexto que debía confiar en OP-A, un token emitido por OP-B.

Acá el RP está federado con dos OPs (**OP-Corp**, legítimo, y **OP-Evil**, del atacante) que firman
con la **misma clave** (comparten infraestructura). La firma es válida para los dos, y el RP acepta
como `aud` cualquiera de sus dos `client_id`. **Lo único que distingue el origen es el claim
`iss`.** Si el RP no lo valida, un id_token de OP-Evil entra en un panel que solo debía confiar en
OP-Corp.

## La mala configuración (en el RP)

```python
# INSEGURO: verifica firma y aud, pero no de qué OP vino
jwt.decode(token, clave, algorithms=["RS256"],
           audience=["caso6-corp", "caso6-evil"])   # falta issuer
```

## La mitigación

- Validar el claim **`iss`** del id_token contra el issuer esperado.
- Usar una **`redirect_uri` distinta por OP** (así la respuesta ya llega atada a un OP).
- Si el OP lo ofrece, validar el **parámetro `iss`** de la respuesta de autorización (RFC 9207).

```python
# SEGURO
jwt.decode(token, clave, algorithms=["RS256"],
           audience=["caso6-corp", "caso6-evil"],
           issuer="http://.../application/o/caso6-corp/")   # exige OP-Corp
```

## Cómo correrlo

```bash
make case6          # abre http://localhost:8081/caso6/insecure
```

1. En `http://localhost:8081/caso6/insecure`:
   - **"Entrar con OP-Corp"** → login legítimo (iss = OP-Corp), aceptado.
   - **"Abrir el ataque del atacante"** → OP-Evil emite un id_token real para la cuenta del
     atacante → **"Inyectar en el panel corporativo"** → el RP lo **acepta** (banner de mix-up).
2. En `http://localhost:8081/caso6/secure`: el mismo token de OP-Evil es **rechazado** (iss no
   coincide).

## Qué observar

- El decodificador resalta el **`iss`**: `.../caso6-corp/` en el legítimo, `.../caso6-evil/` en el
  del atacante.
- Inseguro: acepta el token de OP-Evil en el panel corporativo. Seguro: lo rechaza por `iss`.
- Evidencia en `docker compose logs rp` (`[RP] caso6/... [TOKEN DE OP-EVIL ACEPTADO — MIX-UP]`).

## Reset

```bash
make reset-case6
```

## Blueprint

[`blueprints/case6.yaml`](blueprints/case6.yaml) — `caso6-corp` y `caso6-evil` (misma clave de
firma, distinto `iss`).
