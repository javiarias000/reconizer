#!/usr/bin/env bash
# reconizer.sh - Recon rapido + sugerencia de vectores + exploits listos (modo tutor)
# Uso: ./reconizer.sh <IP> <nombre_maquina> [--quick] [--fuzz]
#   --quick : nmap solo top-1000 puertos (rapido) en vez de -p- (completo)
#   --fuzz  : ademas corre feroxbuster common.txt sobre cada puerto HTTP
# Bitacora: /mnt/c/Users/Javier Arias/Documents/<nombre_maquina>/

set -u
IP="${1:-}"; MAQ="${2:-}"
QUICK=0; FUZZ=0
for a in "${@:3}"; do
  case "$a" in
    --quick) QUICK=1 ;;
    --fuzz)  FUZZ=1 ;;
    *) echo "[!] Flag desconocido: $a"; exit 1 ;;
  esac
done

BITACORA="/mnt/c/Users/Javier Arias/Documents/$MAQ"
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'
say()   { echo -e "${CYN}[*]${NC} $*"; }
ok()    { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; }

if [ -z "$IP" ] || [ -z "$MAQ" ]; then
  echo "reconizer - recon HTB + searchsploit + bitacora"
  echo "Uso: sudo ./reconizer.sh <IP> <nombre_maquina> [--quick] [--fuzz]"
  exit 1
fi

for c in nmap searchsploit curl; do
  command -v "$c" >/dev/null || { fail "Falta $c (instalar en Kali primero)"; exit 1; }
done

echo -e "${CYN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYN}║  RECONIZER - $MAQ ($IP)${NC}"
echo -e "${CYN}╚══════════════════════════════════════════╝${NC}"

# ---------- PASO 0: PROTOCOLO DE RECONEXION ----------
say "PASO 0: Protocolo de reconexion (antes de teorizar NADA)"
if ping -c2 -W2 "$IP" >/dev/null 2>&1; then
  ok "La maquina responde a ping"
else
  warn "NO responde a ping. Si se reinicio la VM, la IP de HTB ROTO."
  echo "    -> Pedir IP nueva, actualizar este comando y la bitacora."
  exit 1
fi
if ! getent hosts "$MAQ.htb" >/dev/null 2>&1; then
  warn "/etc/hosts NO tiene $MAQ.htb (WSL lo borra en cada reinicio). Comando listo:"
  echo "    echo '$IP $MAQ.htb' | sudo tee -a /etc/hosts"
else
  ok "/etc/hosts ya resuelve $MAQ.htb"
fi

mkdir -p "$BITACORA" 2>/dev/null || { fail "No pude crear $BITACORA"; exit 1; }
ok "Bitacora: $BITACORA"

# ---------- PASO 1: NMAP ----------
say "PASO 1: nmap ($([ $QUICK -eq 1 ] && echo 'top-1000' || echo 'todos los puertos'))"
NMAP_OUT="$BITACORA/nmap.txt"
if [ $QUICK -eq 1 ]; then
  NPORTS=""
else
  NPORTS="-p-"
fi
nmap -sV -sC -T4 --min-rate 2000 $NPORTS -oN "$NMAP_OUT" "$IP" >/dev/null 2>&1
ok "nmap guardado en $NMAP_OUT"

# Parsear puertos/servicios (formato legible de nmap: PUERTO open svc VERSION...)
SERVICIOS=$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT")
echo
say "Servicios detectados:"
echo "$SERVICIOS" | sed 's/^/    /'

# ---------- PASO 2: RECON HTTP ----------
PORTS_HTTP=$(grep -E '^[0-9]+/tcp\s+open\s+(http|http-alt|http-proxy|https|https-alt)' "$NMAP_OUT" | cut -d/ -f1)
PORTS_HTTP="$PORTS_HTTP $(grep -iE 'uvicorn|nginx|apache|tomcat|jetty|httpd' "$NMAP_OUT" | grep -E '^[0-9]+/tcp\s+open' | cut -d/ -f1)"
PORTS_HTTP=$(echo "$PORTS_HTTP" | tr ' ' '\n' | sort -u | grep -v '^$' || true)

REDIRECT_DOM=""
for P in $PORTS_HTTP; do
  echo
  say "PASO 2: recon HTTP en puerto $P"
  echo "  --- headers ---"
  curl -si --max-time 10 "http://$IP:$P/" 2>/dev/null | head -12 | sed 's/^/    /'
  TITLE=$(curl -s --max-time 10 "http://$IP:$P/" 2>/dev/null | grep -oiE '<title>[^<]*</title>' | head -1)
  [ -n "$TITLE" ] && echo "  titulo: $TITLE"
  LOC=$(curl -si --max-time 10 "http://$IP:$P/" 2>/dev/null | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
  if [ -n "$LOC" ]; then
    DOM=$(echo "$LOC" | grep -oE 'https?://[^/]+/*' | sed 's#https\?://##;s#/$##')
    warn "REDIRECT a: $LOC"
    [ -n "$DOM" ] && echo "    -> dominio de vhost: $DOM"
    echo "    -> verificar en /etc/hosts y seguir el redirect:"
    echo "       curl -si -H 'Host: $DOM' http://$IP:$P/ | head -20"
    REDIRECT_DOM="$DOM"
  fi
done

# ---------- PASO 3: SEARCHSPLOIT ----------
echo
say "PASO 3: searchsploit por producto+version (todo lo detectado, sin filtro)"
SEARCH_LOG="$BITACORA/searchsploit.txt"
: > "$SEARCH_LOG"
# extraer pares producto version desde el output de nmap
while IFS= read -r line; do
  PORT=$(echo "$line" | cut -d/ -f1)
  SVC=$(echo "$line" | awk '{print $3}')
  # version = 4to campo en adelante (productos con espacios: OpenSSH 9.6p1)
  VER=$(echo "$line" | cut -d' ' -f4- | sed 's/([^)]*)//g; s/^ *//; s/ *$//')
  [ -z "$VER" ] && continue
  echo "------------------------------------------------" >> "$SEARCH_LOG"
  echo "# puerto $PORT ($SVC): $VER" >> "$SEARCH_LOG"
  searchsploit "$VER" 2>/dev/null | head -8 >> "$SEARCH_LOG"
  echo
  echo -e "  ${YLN:-}${YLW}[$PORT/$SVC]${NC} $VER"
  searchsploit --id "$VER" 2>/dev/null | grep -E '\|' | head -5 | sed 's/^/      /'
done <<< "$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT")"
ok "log completo en $SEARCH_LOG"
echo
say "Para traer (mirror) cualquier exploit a la carpeta de la maquina:"
echo "    searchsploit -m <ruta/ID>   # ej: searchsploit -m linux/remote/47168.txt"

# ---------- PASO 4: FUZZING (opcional) ----------
if [ $FUZZ -eq 1 ]; then
  for P in $PORTS_HTTP; do
    echo
    say "PASO 4: feroxbuster en puerto $P"
    feroxbuster -u "http://$IP:$P/" -w /usr/share/seclists/Discovery/Web-Content/common.txt \
      -S 178 -n -d 1 2>/dev/null | grep -E '^\s*[0-9]{3}' | head -15 | sed 's/^/    /'
  done
fi

# ---------- PASO 5: VECTORES SUGERIDOS (playbook de nuestras maquinas) ----------
echo
say "PASO 5: vectores sugeridos segun lo detectado (playbook propio)"
suggest() { echo -e "    ${GRN}→${NC} $*"; }
echo "$SERVICIOS" | grep -qiE 'ssh'     && { echo "  [SSH]"; suggest "Cross-check de la version exacta contra advisories (regreSSHion CVE-2024-6387: parcheado en OpenSSH >=9.6p1-3ubuntu13.3 en noble) antes de intentar nada."; suggest "Prueba de credenciales reutilizadas (misma password en SSH que en DB/otros servicios)."; }
echo "$SERVICIOS" | grep -qiE 'nginx'  && { echo "  [nginx]"; suggest "Redirect a dominio = virtual host routing: mapear dominio en /etc/hosts, enumerar vhosts con feroxbuster -H 'Host: FUZZ.<dominio>' -S <bytes del redirect> -d 0."; }
echo "$SERVICIOS" | grep -qiE 'uvicorn|fastapi' && { echo "  [FastAPI]"; suggest "Pedir /openapi.json y /docs — lista TODOS los endpoints declarados."; suggest "Endpoints que aceptan XML/binary -> probar XXE (entidades file://) y ver DONDE aterriza el resultado (tabla, eco, log)."; }
echo "$NMAP_OUT" >/dev/null; grep -qiE 'java|tomcat|jetty|spring' "$NMAP_OUT" 2>/dev/null && { echo "  [Java/Spring]"; suggest "Error JSON con timestamp/status/error = Spring Boot: probar /actuator y /actuator/heapdump (credenciales en el heap)."; suggest "Si hay heapdump: strings + grep 'jdbc:' como ancla, contexto set* alrededor."; }
echo "$SERVICIOS" | grep -qiE 'clickhouse' && { echo "  [ClickHouse]"; suggest "HTTP en 8123 via vhost db: probar credenciales reutilizadas con basic auth."; suggest "Admin CH = escritura de archivos: INSERT INTO FUNCTION file('<user_files>/x.py', LineAsString) SETTINGS engine_file_truncate_on_insert=1."; }
echo "$SERVICIOS" | grep -qiE 'kafka'     && { echo "  [Kafka/broker]"; suggest "Broker con ACL (tcpwrapped): no atacarlo directo — buscar via indirecta (SSRF/XXE) o la credencial SASL en config/server.properties del foothold."; suggest "Control del broker = control del input de TODOS los consumers (DLQ gatilla procesos periodicos)."; }
[ -n "$REDIRECT_DOM" ] && { echo "  [vhost oculto]"; suggest "Probar credenciales ya conocidas contra TODOS los vhosts nuevos (db., api., portal...) — las credenciales se reutilizan entre capas."; }

# ---------- PASO 6: BITACORA ----------
echo
say "PASO 6: bitacora ($BITACORA)"
[ -f "$BITACORA/writeup.md" ] || cat > "$BITACORA/writeup.md" <<WEOF
# Writeup - $MAQ ($IP)

Fecha: $(date +%Y-%m-%d) | Estado: EN CURSO

## Fase 0 - Recon (reconizer $(date +%H:%M))
Puertos y servicios: ver nmap.txt adjunto.
$(echo "$SERVICIOS" | sed 's/^/    /')

## Fase 1 -
WEOF
[ -f "$BITACORA/credentials.txt" ] || echo "=== CREDENCIALES - $MAQ ($IP) ===" > "$BITACORA/credentials.txt"
[ -f "$BITACORA/errors.md" ]      || { echo "# errors.md - $MAQ"; echo "# error -> causa -> correccion -> leccion"; } > "$BITACORA/errors.md"
ok "writeup.md / credentials.txt / errors.md listos"

echo
ok "RECON COMPLETO. Proximos pasos: leer searchsploit.txt, decidir vector con el tutor, y anotar cada hallazgo en la bitacora."