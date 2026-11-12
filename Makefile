RP := http://localhost:8081
OP := http://localhost:9000
ATTACKER := http://localhost:8082

.PHONY: help up down logs ps reset verify-victim \
        case1 reset-case1 case2 reset-case2 case3 reset-case3 case4 reset-case4 \
        case5 reset-case5 case6 reset-case6

help:
	@echo "Lab OAuth 2.0 / OIDC — Kavacon 2026"
	@echo ""
	@echo "  make up            Levanta el stack (OP + RP + atacante)"
	@echo "  make down          Apaga el stack (conserva ./data)"
	@echo "  make logs          Sigue los logs de todos los servicios"
	@echo "  make ps            Estado de los contenedores"
	@echo "  make reset         Apaga y BORRA ./data (reinicio total del OP)"
	@echo "  make verify-victim Verifica que el OP responde y el blueprint cargo"
	@echo ""
	@echo "  make case1         Imprime/abre la URL de la variante insegura del Caso 1"
	@echo "  make reset-case1   Limpia capturas del atacante y sesion del RP"
	@echo "  make case2         Imprime/abre la URL de la variante insegura del Caso 2"
	@echo "  make reset-case2   Limpia capturas del atacante y sesion del RP"
	@echo "  make case3         Imprime/abre la URL de la variante insegura del Caso 3"
	@echo "  make reset-case3   Limpia capturas del atacante y sesion del RP"
	@echo "  make case4         Imprime/abre la URL del Caso 4 (4b inseguro)"
	@echo "  make reset-case4   Limpia capturas del atacante y sesion del RP"
	@echo "  make case5         Imprime/abre la URL de la variante insegura del Caso 5"
	@echo "  make reset-case5   Limpia la sesion del RP"
	@echo "  make case6         Imprime/abre la URL de la variante insegura del Caso 6"
	@echo "  make reset-case6   Limpia la sesion del RP"

up:
	@test -f .env || (echo 'Falta .env — copia .env.example a .env primero'; exit 1)
	docker compose up -d --build
	@echo "OP:  $(OP)   (akadmin / ver .env)"
	@echo "RP:  $(RP)"
	@echo "ATK: $(ATTACKER)"

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

reset:
	docker compose down -v
	rm -rf ./data
	@echo "Estado borrado. 'make up' arranca de cero."

verify-victim:
	@echo "== OP health =="
	@curl -fsS $(OP)/-/health/ready/ >/dev/null && echo "OP ready: OK" || echo "OP ready: FALLA"
	@echo "== Discovery del provider caso1-insecure =="
	@curl -fsS $(OP)/application/o/caso1-insecure/.well-known/openid-configuration >/dev/null \
	  && echo "provider caso1-insecure: OK (blueprint aplicado)" \
	  || echo "provider caso1-insecure: todavia no (reintenta en unos segundos)"
	@echo ""
	@echo "Login manual de la victima: abri $(OP) e ingresa victima / Kavacon2026!"

# ---------------------------------------------------------------------------
# Caso 1
# ---------------------------------------------------------------------------
case1:
	@echo "Caso 1 — redirect_uri laxa"
	@echo "  INSEGURO: $(RP)/caso1/insecure"
	@echo "  SEGURO:   $(RP)/caso1/secure"
	@echo "  Atacante: $(ATTACKER)/"
	@command -v open >/dev/null && open "$(RP)/caso1/insecure" || true

reset-case1:
	docker compose restart rp attacker
	@echo "Capturas del atacante y sesion del RP limpiadas."
	@echo "Tip: usa una ventana de incognito o borra cookies de localhost para re-loguear a la victima."

# ---------------------------------------------------------------------------
# Caso 2
# ---------------------------------------------------------------------------
case2:
	@echo "Caso 2 — flujos legacy (implicit/hybrid)"
	@echo "  INSEGURO: $(RP)/caso2/insecure"
	@echo "  SEGURO:   $(RP)/caso2/secure"
	@echo "  Atacante: $(ATTACKER)/"
	@command -v open >/dev/null && open "$(RP)/caso2/insecure" || true

reset-case2:
	docker compose restart rp attacker
	@echo "Capturas del atacante y sesion del RP limpiadas."
	@echo "Tip: usa una ventana de incognito o borra cookies de localhost para re-loguear a la victima."

# ---------------------------------------------------------------------------
# Caso 3
# ---------------------------------------------------------------------------
case3:
	@echo "Caso 3 — state / nonce / PKCE (en el RP)"
	@echo "  INSEGURO: $(RP)/caso3/insecure"
	@echo "  SEGURO:   $(RP)/caso3/secure"
	@echo "  Trampa:   $(ATTACKER)/caso3/csrf"
	@command -v open >/dev/null && open "$(RP)/caso3/insecure" || true

reset-case3:
	docker compose restart rp attacker
	@echo "Capturas del atacante y sesion del RP limpiadas."
	@echo "Tip: usa una ventana de incognito o borra cookies de localhost para re-loguear a la victima."

# ---------------------------------------------------------------------------
# Caso 4
# ---------------------------------------------------------------------------
case4:
	@echo "Caso 4 — firma / confusion de algoritmo"
	@echo "  4a HS256 vs RS256: $(RP)/caso4a"
	@echo "  4b INSEGURO:       $(RP)/caso4b/insecure"
	@echo "  4b SEGURO:         $(RP)/caso4b/secure"
	@command -v open >/dev/null && open "$(RP)/caso4b/insecure" || true

reset-case4:
	docker compose restart rp attacker
	@echo "Capturas del atacante y sesion del RP limpiadas."

# ---------------------------------------------------------------------------
# Caso 5
# ---------------------------------------------------------------------------
case5:
	@echo "Caso 5 — scopes amplios / request sin scope"
	@echo "  INSEGURO: $(RP)/caso5/insecure"
	@echo "  SEGURO:   $(RP)/caso5/secure"
	@command -v open >/dev/null && open "$(RP)/caso5/insecure" || true

reset-case5:
	docker compose restart rp attacker
	@echo "Sesion del RP limpiada."

# ---------------------------------------------------------------------------
# Caso 6
# ---------------------------------------------------------------------------
case6:
	@echo "Caso 6 — mix-up / issuer"
	@echo "  INSEGURO: $(RP)/caso6/insecure"
	@echo "  SEGURO:   $(RP)/caso6/secure"
	@command -v open >/dev/null && open "$(RP)/caso6/insecure" || true

reset-case6:
	docker compose restart rp attacker
	@echo "Sesion del RP limpiada."
