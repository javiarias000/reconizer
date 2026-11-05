#!/usr/bin/env bash
# reconizer - CLI de recon para maquinas HTB/lab: nmap + recon HTTP + searchsploit + bitacora
# Uso: reconizer <IP> <nombre_maquina> [flags]
# Bitacora: <dir base>/<nombre_maquina>/ (config: ~/.config/reconizer.conf)

set -u
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'
SPIN="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
say()  { echo -e "${CYN}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }
T0=$(date +%s)

# step_run "<label>" "<comando>" — spinner + cronometro en vivo; al terminar "[+] label (Ns)"
step_run() {
  local label="$1"; local cmd="$2"; local i=0
  bash -c "$cmd" &
  local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r    \033[36m%s\033[0m \033[2m%s...\033[0m  \033[33m%ds\033[0m   " "${SPIN:i%10:1}" "$label" "$i"
    sleep 1; i=$((i+1))
  done
  wait "$pid"; local rc=$?
  printf "\r\033[K"
  if [ $rc -eq 0 ]; then ok "$label  ${DIM}(${i}s)${NC}"; else fail "$label fallo (exit $rc, ${i}s)"; fi
  return $rc
}

usage() {
cat <<EOF
reconizer - recon rapido + vectores sugeridos + exploits listos (modo tutor)

USO:
  reconizer <IP> <nombre_maquina> [flags]

FLAGS:
  --all          nmap -p- (todos los puertos)        [default]
  --quick        nmap solo top-1000 puertos (rapido)
  --deep         -p- + -A (deteccion de OS, traceroute)
  --connect      nmap con -sT (TCP connect scan) — usar para localhost/WSL
  --fuzz         feroxbuster (common.txt) en cada puerto HTTP
  --skip-nmap    no lanzar nmap: reusa <bitacora>/nmap.txt existente
  --set-dir DIR  cambia el directorio base de las auditorias (se recuerda)
  --help         esta ayuda

EJEMPLOS:
  reconizer 10.10.10.5 army --quick
  reconizer 10.10.10.5 army --all --fuzz
  reconizer 10.10.10.5 army --skip-nmap --fuzz
EOF
}

# ---------- parseo ----------
IP="${1:-}"; MAQ="${2:-}"
if [ "$IP" = "--help" ] || [ "$IP" = "-h" ]; then usage; exit 0; fi
MODE=all; FUZZ=0; SKIPNMAP=0; CONNECT=0; NEWDIR=0; SETDIR=""
if [ -z "$IP" ] || [ -z "$MAQ" ]; then usage; exit 1; fi
shift 2
while [ $# -gt 0 ]; do
  case "$1" in
    --all)       MODE=all; shift ;;
    --quick)     MODE=quick; shift ;;
    --deep)      MODE=deep; shift ;;
    --connect)   CONNECT=1; shift ;;
    --fuzz)      FUZZ=1; shift ;;
    --skip-nmap) SKIPNMAP=1; shift ;;
    --set-dir)   SETDIR="${2:-}"; NEWDIR=1; shift 2 ;;
    --set-dir=*) SETDIR="${1#*=}"; NEWDIR=1; shift ;;
    --help|-h)   usage; exit 0 ;;
    *) fail "Flag desconocido: $1 (ver --help)"; exit 1 ;;
  esac
done

for c in nmap searchsploit curl; do
  command -v "$c" >/dev/null || { fail "Falta $c (instalar en Kali)"; exit 1; }
done

echo -e "${CYN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${CYN}║  RECONIZER :: $MAQ ($IP)  ${DIM}[$MODE$([ $FUZZ -eq 1 ] && echo ' +fuzz')]${NC}"
echo -e "${CYN}╚════════════════════════════════════════════════╝${NC}"

# ---------- PASO 0: protocolo de reconexion ----------
say "PASO 0: reconexion  ${DIM}(ping + /etc/hosts)${NC}"
if ping -c2 -W2 "$IP" >/dev/null 2>&1; then
  ok "objetivo responde a ping"
else
  warn "NO responde a ping. Si se reinicio la VM, la IP de HTB ROTO: pedir la nueva y actualizar la bitacora."
fi
if ! getent hosts "$MAQ.htb" >/dev/null 2>&1; then
  warn "/etc/hosts sin $MAQ.htb (WSL lo borra en cada reinicio). Comando listo:"
  echo "    echo '$IP $MAQ.htb' | sudo tee -a /etc/hosts"
fi

# ---------- directorio base (config persistente) ----------
CONF="$HOME/.config/reconizer.conf"
DEFAULT_BASE="/mnt/c/Users/Javier Arias/Documents"
if [ $NEWDIR -eq 1 ]; then
  [ -z "$SETDIR" ] && { fail "--set-dir necesita un directorio"; exit 1; }
  mkdir -p "$(dirname "$CONF")" && echo "BASE=$SETDIR" > "$CONF"
  ok "directorio base guardado: $SETDIR"
  exit 0
fi
if [ -f "$CONF" ] && grep -q '^BASE=' "$CONF"; then
  BASE=$(grep '^BASE=' "$CONF" | cut -d= -f2-)
else
  echo -e "${YLW}[!] Primera vez:${NC} ¿en que directorio quieres guardar las auditorias?"
  echo -e "    ${DIM}(Enter = $DEFAULT_BASE)${NC}"
  printf "    ruta: "
  read -r RESP </dev/tty || RESP=""
  BASE="${RESP:-$DEFAULT_BASE}"
  mkdir -p "$(dirname "$CONF")" && echo "BASE=$BASE" > "$CONF"
  ok "guardado en $CONF  ${DIM}(cambiar: reconizer --set-dir <ruta>)${NC}"
fi
BITACORA="$BASE/$MAQ"
mkdir -p "$BITACORA" 2>/dev/null || { fail "no pude crear $BITACORA"; exit 1; }
ok "bitacora: $BITACORA"

# ---------- PASO 1: nmap ----------
NMAP_OUT="$BITACORA/nmap.txt"
if [ $SKIPNMAP -eq 1 ]; then
  [ -f "$NMAP_OUT" ] || { fail "--skip-nmap pero no existe $NMAP_OUT"; exit 1; }
  say "PASO 1: reusando nmap.txt previo"
else
  say "PASO 1: nmap  ${DIM}($MODE)${NC}"
  case $MODE in
    quick) OPTS="-sV -sC -T4 -Pn --top-ports 1000" ;;
    all)   OPTS="-sV -sC -T4 -Pn --min-rate 2000 -p-" ;;
    deep)  OPTS="-sV -sC -A -T4 -Pn --min-rate 2000 -p-" ;;
  esac
  # --connect: TCP connect scan (-sT) — necesario para localhost (WSL2 no responde SYN raw a su propio loopback)
  [ $CONNECT -eq 1 ] && OPTS="-sT $(echo "$OPTS" | sed 's/^-sV //')"
  step_run "nmap escaneando" "nmap $OPTS -oN '$NMAP_OUT' '$IP'"
fi

SERVICIOS=$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT")
NPORT=$(echo "$SERVICIOS" | grep -c .)
echo
say "servicios: ${GRN}${NPORT} puertos abiertos${NC}"
echo "$SERVICIOS" | sed 's/^/    /'

# ---------- PASO 2: recon HTTP (solo headers clave) ----------
RAW_NMAP=$(cat "$NMAP_OUT")
PORTS_HTTP=$( { grep -E '^[0-9]+/tcp\s+open\s+http' "$NMAP_OUT" | cut -d/ -f1
  echo "$RAW_NMAP" | grep -iE 'uvicorn|nginx|apache|tomcat|jetty|httpd|gunicorn' | grep -E '^[0-9]+/tcp\s+open' | cut -d/ -f1
} | sort -u | grep -v '^$' || true )
REDIRECT_DOM=""
for P in $PORTS_HTTP; do
  echo
  say "PASO 2: HTTP en :$P  ${DIM}(headers clave)${NC}"
  curl -si --max-time 10 "http://$IP:$P/" 2>/dev/null \
    | grep -iE '^(HTTP/|server:|location:|x-powered|content-type:)' | head -6 | sed 's/^/    /'
  LOC=$(curl -si --max-time 10 "http://$IP:$P/" 2>/dev/null | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
  if [ -n "$LOC" ]; then
    DOM=$(echo "$LOC" | grep -oE 'https?://[^/]+' | sed 's#https\?://##')
    warn "redirect -> $LOC  ${DIM}(posible vhost: $DOM)${NC}"
    echo "    ${DIM}verificar: curl -si -H 'Host: $DOM' http://$IP:$P/ | head${NC}"
    REDIRECT_DOM="$DOM"
  fi
done

# ---------- PASO 3: searchsploit ----------
echo
say "PASO 3: searchsploit por cada version  ${DIM}(conteo de exploits por servicio)${NC}"
SEARCH_LOG="$BITACORA/searchsploit.txt"
SSTART=$(date +%s)
: > "$SEARCH_LOG"
while IFS= read -r line; do
  PORT=$(echo "$line" | cut -d/ -f1)
  SVC=$(echo "$line" | awk '{print $3}')
  VER=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/([^)]*)//g; s/^ *//; s/ *$//')
  [ -z "$VER" ] && continue
  {
    echo "------------------------------------------------"
    echo "# puerto $PORT ($SVC): $VER"
    searchsploit "$VER" 2>/dev/null | head -10
  } >> "$SEARCH_LOG"
  NEXP=$(searchsploit --id "$VER" 2>/dev/null | grep -cE '\|')
  echo -e "    ${YLW}[$PORT/$SVC]${NC} $VER  ${DIM}-> ${NEXP} exploits${NC}"
done <<< "$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT")"
SDUR=$(( $(date +%s) - SSTART ))
ok "searchsploit  ${DIM}(${SDUR}s)${NC} -> $SEARCH_LOG"
say "bajar un exploit (mirror):  ${DIM}searchsploit -m <ruta-del-exploit>${NC}"

# ---------- PASO 4: fuzzing ----------
if [ $FUZZ -eq 1 ]; then
  echo
  if ! command -v feroxbuster >/dev/null; then
    warn "feroxbuster no instalado (sudo apt install feroxbuster) — saltando"
  else
    for P in $PORTS_HTTP; do
      say "PASO 4: feroxbuster en :$P"
      FUZZOUT="$BITACORA/ferox_$P.txt"
      step_run "fuzz :$P" "feroxbuster -u 'http://$IP:$P/' -w /usr/share/seclists/Discovery/Web-Content/common.txt -S 178 -n -d 1 >'$FUZZOUT' 2>&1"
      NF=$(grep -cE '^\s*(200|201|204|301|302|307|401|403|405|500)' "$FUZZOUT" 2>/dev/null || echo 0)
      ok "rutas interesantes en :$P: ${NF}  ${DIM}->$FUZZOUT${NC}"
      grep -E '^\s*(200|201|204|301|302|307|401|403|405|500)' "$FUZZOUT" 2>/dev/null | head -10 | sed 's/^/      /'
    done
  fi
fi

# ---------- PASO 5: vectores sugeridos (playbook) ----------
echo
say "PASO 5: vectores sugeridos  ${DIM}(playbook de nuestras maquinas)${NC}"
suggest() { echo -e "    ${GRN}→${NC} $*"; }
echo "$RAW_NMAP" | grep -qiE 'openssh|ssh' && { echo "  ${YLW}[SSH]${NC}"; suggest "cross-check version exacta vs advisories (regreSSHion CVE-2024-6387: parcheado en noble >= 9.6p1-3ubuntu13.3)."; suggest "credenciales reutilizadas: probar cada password conocida contra SSH."; }
echo "$RAW_NMAP" | grep -qiE 'nginx|apache|httpd' && { echo "  ${YLW}[web]${NC}"; suggest "redirect a dominio = vhost routing: mapear /etc/hosts y fuzzear 'Host: FUZZ.<dominio>' -S <bytes redirect> -d 0."; }
echo "$RAW_NMAP" | grep -qiE 'uvicorn|fastapi|gunicorn' && { echo "  ${YLW}[FastAPI]${NC}"; suggest "pedir /openapi.json y /docs — mapa de endpoints."; suggest "endpoints XML/binary -> XXE (file://) y buscar DONDE aterriza el resultado (tabla, eco, log)."; }
echo "$RAW_NMAP" | grep -qiE 'java|tomcat|jetty|spring' && { echo "  ${YLW}[Java/Spring]${NC}"; suggest "error JSON timestamp/status/error = Spring Boot: /actuator y /actuator/heapdump."; suggest "heapdump: strings + ancla 'jdbc:' + contexto set* (credenciales Hikari)."; }
echo "$RAW_NMAP" | grep -qiE 'clickhouse|8123' && { echo "  ${YLW}[ClickHouse]${NC}"; suggest "HTTP 8123 via vhost db.*: basic auth con credenciales reutilizadas."; suggest "admin CH = escritura: INSERT INTO FUNCTION file('<user_files>/x.py', LineAsString) SETTINGS engine_file_truncate_on_insert=1."; }
echo "$RAW_NMAP" | grep -qiE 'kafka|zookeeper|9092' && { echo "  ${YLW}[Kafka]${NC}"; suggest "broker ACL (tcpwrapped): NO directo. SASL en server.properties del foothold; DLQ gatilla procesos periodicos."; }
[ -n "$REDIRECT_DOM" ] && { echo "  ${YLW}[vhost]${NC}"; suggest "probar TODAS las credenciales conocidas contra cada vhost nuevo: se reutilizan entre capas."; }

# ---------- PASO 6: bitacora ----------
echo
say "PASO 6: bitacora"
[ -f "$BITACORA/writeup.md" ] || cat > "$BITACORA/writeup.md" <<WEOF
# Writeup - $MAQ ($IP)

Fecha: $(date +%Y-%m-%d) | Estado: EN CURSO

## Fase 0 - Recon (reconizer $(date +%H:%M), modo $MODE)
$(echo "$SERVICIOS" | sed 's/^/    /')

## Fase 1 -
WEOF
[ -f "$BITACORA/credentials.txt" ] || echo "=== CREDENCIALES - $MAQ ($IP) ===" > "$BITACORA/credentials.txt"
[ -f "$BITACORA/errors.md" ] || printf "# errors.md - $MAQ\n# error -> causa -> correccion -> leccion\n" > "$BITACORA/errors.md"
ok "writeup.md / credentials.txt / errors.md listos"

TOTAL=$(( $(date +%s) - T0 ))
echo
echo -e "${CYN}══════════════════════════════════════════════════${NC}"
echo -e "${GRN}  RECON COMPLETO${NC}  ${DIM}tiempo total: ${TOTAL}s (~$(( TOTAL / 60 ))m)${NC}"
echo -e "  bitacora: $BITACORA"
echo -e "  siguiente: repasar searchsploit.txt con el tutor y decidir el vector."
echo -e "${CYN}══════════════════════════════════════════════════${NC}"