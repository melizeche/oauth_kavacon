# Laboratorio OAuth 2.0 / OpenID Connect — Kavacon 2026

Un laboratorio para mostrar ataques a OAuth 2.0 y OpenID Connect que salen de una mala
configuración, no de romper criptografía ni de un bug del proveedor de identidad. Un IdP puede
estar certificado por la OpenID Foundation y aun así dejar robar una cuenta si lo configuraste
mal, o si el cliente verifica mal los tokens.

## Antes de empezar

Tres cosas para dejar claras:

- Los defaults de un IdP moderno son razonablemente seguros. Todo lo que hay acá requiere
  desviarse de ellos a propósito.
- Este lab está mal configurado a propósito, aislado y para uso educativo. No es una instalación
  normal y no debería exponerse a una red real.
- No es sobre un producto puntual. Las mismas malas configuraciones aparecen en Keycloak, Okta,
  Entra ID o Auth0. Cada caso se describe contra el RFC correspondiente y el comportamiento del
  cliente. Uso authentik porque es open source y se automatiza con blueprints.

## Arquitectura

Tres piezas en contenedores sobre una red aislada:

| Pieza | Puerto | Rol |
|-------|--------|-----|
| OP | `9000` | OpenID Provider (IdP open source). Se configura por caso con blueprints. |
| RP | `8081` | Relying Party: cliente Flask vulnerable. Una ruta por caso y variante. |
| Atacante | `8082` | Recibe y loguea codes, tokens y fragments. |

Todo se publica en `localhost` con puertos distintos, así corre en un navegador normal sin tocar
DNS. El `redirect_uri` legítimo del RP es `http://localhost:8081/callback`.

En producción el atacante estaría en otro dominio. Acá, para no depender de DNS, es otro puerto
(`8082`) de `localhost`. La falla es la misma: el OP entrega el `code` o el token a una
`redirect_uri` que no debería haber aceptado. Si querés verlo con dominios de verdad, mirá la
sección de modo dominio más abajo.

## Requisitos

- Docker + Docker Compose.
- Puertos libres: `9000`, `9443`, `8081`, `8082`.

## Cómo levantarlo

```bash
cp .env.example .env
# editá .env: al menos AUTHENTIK_SECRET_KEY (openssl rand -base64 48)
make up
```

El primer arranque tarda, porque el OP corre migraciones y aplica los blueprints. Esperá a que
`make verify-victim` responda OK.

Antes de las demos, probá el login de la víctima en `http://localhost:9000`:

```
usuario:     victima
contraseña:  12345
```

El admin es `akadmin`, con la contraseña de `AUTHENTIK_BOOTSTRAP_PASSWORD` del `.env`.

## Los casos

| Caso | Dónde falla | Qué se ataca |
|------|-------------|--------------|
| [1](cases/01-redirect-uri/) | Config del OP | `redirect_uri` laxa, robo del `code` |
| [2](cases/02-legacy-flows/) | Config del OP | Flujos legacy (implicit/hybrid), token en el `#fragment` |
| [3](cases/03-state-nonce-pkce/) | Cliente (RP) | Falta de `state`, `nonce` o PKCE |
| [4](cases/04-signature/) | OP + cliente | Firma simétrica vs asimétrica; confusión de algoritmo |
| [5](cases/05-broad-scopes/) | Config del OP | Scopes amplios, request sin `scope` |
| [6](cases/06-mixup-issuer/) | Cliente (RP) | Mix-up: el cliente no valida el `issuer` |

Cada carpeta en `cases/` tiene su README con qué se ataca, cómo correrlo, qué mirar y la
mitigación.

## Por qué cambiar de caso es solo abrir una URL

Los blueprints se cargan todos juntos al arranque. Cada caso define sus aplicaciones y providers,
con su propio `client_id`, `client_secret` y `slug`. Donde hay variante segura e insegura, las dos
coexisten (por ejemplo `caso1-insecure` y `caso1-secure`); ninguna se muta en caliente. El RP sirve
todos los casos a la vez, una ruta por variante. Así no hay que reiniciar nada para cambiar de caso:
`make caseN` solo imprime o abre la URL.

## Modo dominio (opcional, solo Caso 1)

Por defecto el lab corre en modo puerto: todo en `localhost`, sin tocar `/etc/hosts`. En el Caso 1
el "dominio del atacante" es en realidad otro puerto (`:8082`), que la regex mal escrita
`http://localhost:808.\/callback` matchea.

Si querés que el Caso 1 se vea con dominios (un look-alike que matchea la regex), hay un modo
opcional con un proxy Caddy en `:80` y nombres `.test`:

```bash
make hosts        # agrega op.lab.test / rp.lab.test / rp-lab.test a /etc/hosts (pide sudo)
make up-domain    # levanta el stack + proxy; Caso 1 bajo dominios
```

El RP legítimo queda en `http://rp.lab.test/callback` y el atacante en
`http://rp-lab.test/callback`. La regex insegura `http://rp.lab.test/callback`, con los puntos sin
escapar, matchea `rp-lab.test` porque el primer `.` matchea el `-`; el `strict` del seguro lo
rechaza. El resto del lab sigue en `localhost`.

Para volver a modo puerto: `make down-domain && make reset && make up`. Hay que resetear porque
authentik no re-aplica el blueprint si solo cambió la variable de entorno y no el archivo.
`make unhosts` quita las entradas de `/etc/hosts`.

## Comandos

```bash
make up            # levanta el stack
make down          # lo apaga (conserva ./data)
make logs          # sigue logs
make reset         # apaga y borra ./data (reinicio total del OP)
make case1         # imprime o abre la URL de la variante insegura del caso 1
make reset-case1   # limpia capturas del atacante y la sesión del RP
```
