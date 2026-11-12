# Laboratorio OAuth 2.0 / OpenID Connect — Kavacon 2026

> ## ⚠️ Antes de empezar
>
> - **Los valores por defecto de un IdP moderno son razonablemente seguros.** Todo lo que
>   se muestra aquí requiere *desviarse* de esos defaults a propósito.
> - **Este laboratorio está mal configurado a propósito**, en un entorno aislado y con
>   fines educativos. **No es una instalación normal** y no debe exponerse a una red real.
> - **Es independiente del producto.** Las mismas malas configuraciones se cometen en
>   Keycloak, Okta, Entra ID o Auth0. Cada falla se describe en términos del **estándar**
>   (el RFC correspondiente) y del comportamiento del **cliente**, no de un producto.
>
> El objetivo es **entender para defender**.

## Qué es

Un laboratorio que demuestra ataques a OAuth 2.0 / OpenID Connect causados por **mala
configuración** — no por romper criptografía ni por bugs del proveedor de identidad. Un IdP
puede estar certificado por la OpenID Foundation y aun así dejar robar una cuenta si **vos** lo
configuraste mal, o si el **cliente** verifica mal los tokens.

## Arquitectura

Tres piezas en contenedores sobre una red aislada:

| Pieza        | Puerto | Rol                                                             |
|--------------|--------|-----------------------------------------------------------------|
| **OP**       | `9000` | OpenID Provider (IdP open source). Se configura por caso con blueprints. |
| **RP**       | `8081` | Relying Party: cliente Flask vulnerable. Una ruta por caso/variante. |
| **ATTACKER** | `8082` | Servidor del atacante: recibe y loguea codes, tokens y fragments. |

Todo se publica en `localhost` con puertos distintos; no hace falta DNS. El `redirect_uri`
legítimo del RP es `http://localhost:8081/callback`.

> **Sobre el "dominio" del atacante:** en producción el atacante estaría en otro dominio.
> Aquí, para que las demos corran en un navegador normal sin tocar DNS, el atacante es
> simplemente **otro puerto** (`8082`) de `localhost`. La falla es idéntica: el OP entrega el
> `code`/token a una `redirect_uri` que no debería haber aceptado.

## Requisitos

- Docker + Docker Compose.
- Puertos libres: `9000`, `9443`, `8081`, `8082`.

## Cómo levantarlo

```bash
cp .env.example .env
# editá .env: al menos AUTHENTIK_SECRET_KEY (openssl rand -base64 48)
make up
```

El primer arranque tarda: el OP corre migraciones y aplica los blueprints. Esperá a que
`make verify-victim` diga OK.

```bash
make verify-victim   # chequea que el OP responde y el provider del caso 1 existe
```

**Login de la víctima** (verificalo antes de las demos): abrí `http://localhost:9000`
e ingresá con:

```
usuario:     victima
contraseña:  Kavacon2026!
```

El admin es `akadmin` con la contraseña de `AUTHENTIK_BOOTSTRAP_PASSWORD` del `.env`.

## Diseño: cambiar de caso es abrir una URL

Los blueprints se cargan **todos de una** al arranque. Cada caso define sus aplicaciones y
providers con su propio `client_id`/`client_secret`/`slug`, y donde hay variante segura e
insegura **ambas coexisten** (p. ej. `caso1-insecure` y `caso1-secure`), nunca una que se
muta. El RP sirve todos los casos a la vez, una ruta por variante. Por eso **no se reinicia
nada** para cambiar de caso: `make caseN` solo imprime/abre la URL.

## Casos

| Caso | Dónde está la falla | Qué se ataca |
|------|---------------------|--------------|
| [1](cases/01-redirect-uri/) | Config del OP | `redirect_uri` laxa → robo del `code` |
| [2](cases/02-legacy-flows/) | Config del OP | Flujos legacy (implicit/hybrid) → token en el `#fragment` |
| [3](cases/03-state-nonce-pkce/) | Cliente (RP) | Falta de `state` / `nonce` / PKCE |
| [4](cases/04-signature/) | OP + Cliente | Firma simétrica vs asimétrica; confusión de algoritmo |
| [5](cases/05-broad-scopes/) | Config del OP | Scopes amplios / request sin `scope` |
| [6](cases/06-mixup-issuer/) | Cliente (RP) | Mix-up: el cliente no valida el `issuer` |

*(El repo se construye caso por caso; ver cada carpeta en `cases/`.)*

## Comandos

```bash
make up            # levanta el stack
make down          # lo apaga (conserva ./data)
make logs          # sigue logs
make reset         # apaga y borra ./data (reinicio total del OP)
make case1         # imprime/abre la URL de la variante insegura del caso 1
make reset-case1   # limpia capturas del atacante y sesión del RP
```
