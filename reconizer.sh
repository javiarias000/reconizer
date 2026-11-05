#!/usr/bin/env bash
# reconizer - CLI de recon para maquinas HTB/lab: nmap + recon HTTP + searchsploit + VERIFICACION ACTIVA
# Uso: reconizer <IP> <nombre_maquina> [flags]
# Bitacora: <dir base>/<nombre_maquina>/ (config: ~/.config/reconizer.conf)
#
# REGLA DEL SCRIPT: nunca emite suposiciones. Un veredicto de VULNERABLE / NO_VULNERABLE
# solo aparece cuando una prueba real se ejecuto contra el servicio y se observo la respuesta.
# searchsploit solo genera CANDIDATOS; la verificacion activa los confirma o descarta.

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
reconizer - recon rapido + CANDIDATOS (searchsploit) + verificacion ACTIVA de vulnerabilidades

Regla: el script solo informa VULNERABLE / NO VULNERABLE cuando PROBO algo contra el
servicio y observo la respuesta. Las suposiciones no aparecen en los veredictos.

USO:
  reconizer <IP> <nombre_maquina> [flags]

FLAGS:
  --all          nmap -p- (todos los puertos)        [default]
  --quick        nmap solo top-1000 puertos (rapido)
  --deep         -p- + -A (deteccion de OS, traceroute)
  --connect      nmap con -sT (TCP connect scan) — usar para localhost/WSL
  --fuzz         feroxbuster (common.txt) en cada puerto HTTP
  --skip-nmap    no lanzar nmap: reusa <bitacora>/nmap.txt existente
  --skip-vuln    no lanzar la verificacion activa (PASO 4)
  --domain DOM   dominio a verificar contra la IP (el script NO inventa dominios:
                  comprueba DNS + respuesta HTTP con cabecera Host antes de afirmar nada)
  --set-dir DIR  cambia el directorio base de las auditorias (se recuerda)
  --help         esta ayuda

EJEMPLOS:
  reconizer 10.10.10.5 army --quick
  reconizer 10.10.10.5 army --all --fuzz
  reconizer 10.10.10.5 army --skip-nmap
  reconizer 10.129.145.124 stream --domain htb-airport.htb
EOF
}

# ---------- parseo ----------
IP="${1:-}"; MAQ="${2:-}"
if [ "$IP" = "--help" ] || [ "$IP" = "-h" ]; then usage; exit 0; fi
MODE=all; FUZZ=0; SKIPNMAP=0; SKIPVULN=0; CONNECT=0; NEWDIR=0; SETDIR=""; DOMAIN=""
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
    --skip-vuln) SKIPVULN=1; shift ;;
    --domain)    DOMAIN="${2:-}"; shift 2 ;;
    --domain=*)  DOMAIN="${1#*=}"; shift ;;
    --set-dir)   SETDIR="${2:-}"; NEWDIR=1; shift 2 ;;
    --set-dir=*) SETDIR="${1#*=}"; NEWDIR=1; shift ;;
    --help|-h)   usage; exit 0 ;;
    *) fail "Flag desconocido: $1 (ver --help)"; exit 1 ;;
  esac
done

for c in nmap searchsploit curl timeout; do
  command -v "$c" >/dev/null || { fail "Falta $c (instalar en Kali)"; exit 1; }
done

echo -e "${CYN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${CYN}║  RECONIZER :: $MAQ ($IP)  ${DIM}[$MODE$([ $FUZZ -eq 1 ] && echo ' +fuzz')]${NC}"
echo -e "${CYN}╚════════════════════════════════════════════════╝${NC}"

# ---------- PASO 0: protocolo de reconexion + verificacion de dominio ----------
say "PASO 0: reconexion  ${DIM}(ping)${NC}"
if ping -c2 -W2 "$IP" >/dev/null 2>&1; then
  ok "objetivo responde a ping"
else
  warn "NO responde a ping (o ICMP bloqueado: no descarta que TCP este vivo). Si la IP cambio, actualizar la bitacora."
fi
DOM_STATE="sin_dominio"
if [ -n "$DOMAIN" ]; then
  say "PASO 0b: verificacion del dominio '$DOMAIN' contra $IP  ${DIM}(nada se asume)${NC}"
  RES=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1)
  if [ -n "$RES" ] && [ "$RES" = "$IP" ]; then
    ok "DNS: $DOMAIN resuelve a $IP (comprobado con getent)"
    DOM_STATE="dns_ok"
  elif [ -n "$RES" ]; then
    warn "DNS: $DOMAIN resuelve a $RES, NO a $IP. Ese dominio pertenece a OTRO host: no usarlo contra esta IP."
    DOM_STATE="dns_otro_host"
  else
    warn "DNS: $DOMAIN no tiene registro publico que resuelva. Si es vhost interno/solo-lab, apuntarlo y el script lo verificara por HTTP:"
    echo "    echo '$IP $DOMAIN' | sudo tee -a /etc/hosts   # luego re-ejecutar con --domain"
    DOM_STATE="sin_registro"
  fi
  echo -e "    ${DIM}estado DNS: $DOM_STATE (la prueba HTTP va en el PASO 2, con los puertos conocidos)${NC}"
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
    REDIRECT_DOM="$DOM"
  fi
done

# verificacion HTTP del dominio dado (--domain): comparar respuesta con y sin cabecera Host
if [ -n "$DOMAIN" ] && [ -n "$PORTS_HTTP" ]; then
  say "PASO 2b: prueba HTTP del dominio '$DOMAIN'  ${DIM}(con y sin cabecera Host)${NC}"
  for P in $PORTS_HTTP; do
    BASE_RSP=$(curl -s --max-time 8 -o /dev/null -w '%{http_code}:%{size_download}' "http://$IP:$P/")
    DOM_RSP=$(curl -s --max-time 8 -H "Host: $DOMAIN" -o /dev/null -w '%{http_code}:%{size_download}' "http://$IP:$P/")
    if [ "$BASE_RSP" = "0:0" ] && [ "$DOM_RSP" = "0:0" ]; then
      say "vhost '$DOMAIN' en :$P INDETERMINADO: el puerto HTTP no respondio (sin evidencia, no se afirma nada)"
    elif [ "$DOM_RSP" != "$BASE_RSP" ]; then
      ok "VHOST CONFIRMADO en :$P  ${DIM}| prueba: GET / con Host: $DOMAIN vs sin cabecera | evidencia: respuesta cambia ($BASE_RSP -> $DOM_RSP)${NC}"
    else
      echo -e "    ${DIM}vhost '$DOMAIN' en :$P NO confirmado | prueba: GET / con Host: $DOMAIN | evidencia: respuesta identica ($DOM_RSP)${NC}"
    fi
  done
elif [ -n "$DOMAIN" ]; then
  warn "no hay puertos HTTP para probar el dominio '$DOMAIN': sin verificacion HTTP posible"
fi

# ---------- PASO 3: searchsploit (solo genera CANDIDATOS, no veredictos) ----------
echo
say "PASO 3: searchsploit por cada version  ${DIM}(CANDIDATOS, no veredictos)${NC}"
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
  echo -e "    ${YLW}[$PORT/$SVC]${NC} $VER  ${DIM}-> ${NEXP} exploits candidatos${NC}"
done <<< "$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT")"
SDUR=$(( $(date +%s) - SSTART ))
ok "searchsploit  ${DIM}(${SDUR}s)${NC} -> $SEARCH_LOG"
warn "TODO lo anterior son CANDIDATOS (correlacion version/exploit en base de datos). El PASO 4 prueba en vivo y solo ese emite veredictos."

# ---------- PASO 4: VERIFICACION ACTIVA (solo hechos probados contra el objetivo) ----------
if [ $SKIPVULN -eq 1 ]; then
  echo
  warn "PASO 4 omitido (--skip-vuln): sin veredictos, solo candidatos."
else
  echo
  say "PASO 4: verificacion ACTIVA  ${DIM}(cada veredicto viene de una prueba real contra $IP)${NC}"
  VERIF_LOG="$BITACORA/verificacion.txt"
  : > "$VERIF_LOG"

  # report <VULNERABLE|NO_VULNERABLE|HECHO> "<objetivo>" "<prueba ejecutada>" "<evidencia observada>"
  report() {
    local state="$1" tgt="$2" t="$3" ev="$4"
    case "$state" in
      VULNERABLE)
        ok "VULNERABLE  $tgt  ${DIM}| prueba: $t | evidencia: $ev${NC}"
        echo "[VULNERABLE] $tgt | prueba: $t | evidencia: $ev" >> "$VERIF_LOG" ;;
      HECHO)
        say "HECHO       $tgt  ${DIM}| prueba: $t | evidencia: $ev${NC}"
        echo "[HECHO] $tgt | prueba: $t | evidencia: $ev" >> "$VERIF_LOG" ;;
      *)
        echo -e "    ${DIM}NO vulnerable  $tgt  | prueba: $t | evidencia: $ev${NC}"
        echo "[NO_VULNERABLE] $tgt | prueba: $t | evidencia: $ev" >> "$VERIF_LOG" ;;
    esac
  }

  # util: conecta a IP:PORT con timeout -> exit 0 si el TCP abre
  tcp_open() { timeout "${3:-3}" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
  # util: envia payload crudo por TCP y devuelve la respuesta
  tcp_send() { timeout "${4:-6}" bash -c "exec 3<>/dev/tcp/$1/$2; printf '%b' '$3' >&3; cat <&3" 2>/dev/null; }

  # 4a) nmap NSE: scripts de vulnerabilidad sobre TODOS los puertos abiertos (prueba activa real)
  OPENPORTS=$(echo "$SERVICIOS" | cut -d/ -f1 | paste -sd, -)
  NSE_OUT="$BITACORA/nmap_vuln.txt"
  step_run "nmap NSE vuln scripts (puertos: $OPENPORTS)" "nmap -Pn -sV --script 'vuln and not dos' -p '$OPENPORTS' -oN '$NSE_OUT' '$IP' >/dev/null 2>&1"
  awk '/^\|[ _]/ {
    if (match($0, /^\|[ ]+[^:|]+:/)) { cur=substr($0, RSTART+2, RLENGTH-3); gsub(/^[ ]+|[ ]+$/, "", cur) }
    if ($0 ~ /VULNERABLE/ && $0 !~ /[Nn]ot vulnerable/ && cur != "") print cur
  }' "$NSE_OUT" | sort -u | while read -r v; do
    report VULNERABLE "$IP (NSE: $v)" "nmap --script 'vuln and not dos' contra puertos abiertos" "script NSE reporta VULNERABLE (detalle: nmap_vuln.txt)"
  done
  grep -q 'VULNERABLE' "$NSE_OUT" 2>/dev/null || say "NSE: ningun script reporto VULNERABLE (pruebas ejecutadas, todas negativas)"

  # 4b) sondas especificas por servicio: cada una ENVIA algo y OBSERVA la respuesta
  while IFS= read -r line; do
    PORT=$(echo "$line" | cut -d/ -f1)
    SVC=$(echo "$line" | awk '{print $3}')
    VER=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/([^)]*)//g; s/^ *//; s/ *$//')

    case "$SVC" in
    ftp)
      # vsftpd 2.3.4: el backdoor abre 6200 tras un login malicioso. Se prueba de verdad.
      if echo "$VER" | grep -q 'vsftpd 2\.3\.4'; then
        tcp_send "$IP" "$PORT" 'USER t:)\r\nPASS x\r\nQUIT\r\n' 6 >/dev/null 2>&1; sleep 3
        if tcp_open "$IP" 6200 2; then
          report VULNERABLE ":$PORT ftp (vsftpd 2.3.4)" "login 'USER t:)' + intento de conexion a 6200" "puerto 6200 ABIERTO tras el login malicioso: backdoor confirmado"
        else
          report NO_VULNERABLE ":$PORT ftp (vsftpd 2.3.4)" "login 'USER t:)' + intento de conexion a 6200" "6200 cerrado: el backdoor no se activo"
        fi
      fi
      # ProFTPD mod_copy (CVE-2015-3306): SITE CPFR sin autenticar
      if echo "$VER" | grep -qi proftpd; then
        RESP=$(tcp_send "$IP" "$PORT" 'SITE CPFR /etc/passwd\r\nQUIT\r\n' 6 2>/dev/null | tr -d '\r')
        if echo "$RESP" | grep -q '^350'; then
          report VULNERABLE ":$PORT ftp ($VER)" "SITE CPFR /etc/passwd sin login" "respuesta 350: mod_copy permite copiar archivos sin autenticacion"
        else
          report NO_VULNERABLE ":$PORT ftp ($VER)" "SITE CPFR /etc/passwd sin login" "sin 350 (respuesta: $(echo "$RESP" | head -1))"
        fi
      fi
      # FTP anonimo: hecho probado (no es veredicto de CVE, es acceso observado)
      RESP=$(tcp_send "$IP" "$PORT" 'USER anonymous\r\nPASS a@b.c\r\nQUIT\r\n' 6 2>/dev/null | tr -d '\r')
      if echo "$RESP" | grep -q '^230'; then
        report HECHO ":$PORT ftp" "login anonymous / a@b.c" "230 login correcto: FTP anonimo activo"
      fi
      ;;
    http|https|http-alt|http-proxy)
      # Spring Boot actuator expuesto
      for path in /actuator/heapdump /actuator/env; do
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "http://$IP:$PORT$path")
        if [ "$code" = "200" ]; then
          report VULNERABLE ":$PORT http" "GET $path" "HTTP 200: actuator expuesto"
        else
          report NO_VULNERABLE ":$PORT http" "GET $path" "HTTP $code"
        fi
      done
      # Tomcat manager sin credenciales
      code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "http://$IP:$PORT/manager/html")
      if [ "$code" = "200" ]; then
        report VULNERABLE ":$PORT http (tomcat)" "GET /manager/html sin credenciales" "HTTP 200: manager accesible"
      else
        report NO_VULNERABLE ":$PORT http (tomcat)" "GET /manager/html sin credenciales" "HTTP $code"
      fi
      # WebDAV: PROPFIND y PUT anonimo (la escritura es lo explotable)
      code=$(curl -sk -X PROPFIND -H 'Depth: 0' -o /dev/null -w '%{http_code}' --max-time 8 "http://$IP:$PORT/")
      if [ "$code" = "207" ]; then
        PUTCODE=$(curl -sk -X PUT -d 'davtest' -o /dev/null -w '%{http_code}' --max-time 8 "http://$IP:$PORT/davtest.txt")
        if [ "$PUTCODE" = "201" ] || [ "$PUTCODE" = "204" ]; then
          report VULNERABLE ":$PORT http" "PROPFIND / (207) + PUT /davtest.txt" "HTTP $PUTCODE: WebDAV con escritura anonima"
        else
          report HECHO ":$PORT http" "PROPFIND / (207) + PUT /davtest.txt" "WebDAV activo pero PUT anonimo devolvio $PUTCODE (sin escritura)"
        fi
      fi
      ;;
    esac
  done <<< "$SERVICIOS"

  NCONF=$(grep -c '^\[VULNERABLE\]' "$VERIF_LOG")
  ok "verificacion: ${GRN}${NCONF} vulnerabilidades CONFIRMADAS por prueba activa${NC} -> $VERIF_LOG"
fi

# ---------- PASO 5: fuzzing ----------
if [ $FUZZ -eq 1 ]; then
  echo
  if ! command -v feroxbuster >/dev/null; then
    warn "feroxbuster no instalado (sudo apt install feroxbuster) — saltando"
  else
    for P in $PORTS_HTTP; do
      say "PASO 5: feroxbuster en :$P"
      FUZZOUT="$BITACORA/ferox_$P.txt"
      step_run "fuzz :$P" "feroxbuster -u 'http://$IP:$P/' -w /usr/share/seclists/Discovery/Web-Content/common.txt -S 178 -n -d 1 >'$FUZZOUT' 2>&1"
      NF=$(grep -cE '^\s*(200|201|204|301|302|307|401|403|405|500)' "$FUZZOUT" 2>/dev/null || echo 0)
      ok "rutas interesantes en :$P: ${NF}  ${DIM}->$FUZZOUT${NC}"
      grep -E '^\s*(200|201|204|301|302|307|401|403|405|500)' "$FUZZOUT" 2>/dev/null | head -10 | sed 's/^/      /'
    done
  fi
fi

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
echo -e "  ${GRN}RECON COMPLETO${NC}  ${DIM}tiempo total: ${TOTAL}s (~$(( TOTAL / 60 ))m)${NC}"
echo -e "  bitacora: $BITACORA"
VERIF_LOG="$BITACORA/verificacion.txt"
if [ -f "$VERIF_LOG" ] && grep -q '^\[VULNERABLE\]' "$VERIF_LOG"; then
  NCONF=$(grep -c '^\[VULNERABLE\]' "$VERIF_LOG")
  echo -e "  ${RED}vulnerabilidades CONFIRMADAS por prueba activa: $NCONF${NC}"
  grep '^\[VULNERABLE\]' "$VERIF_LOG" | sed 's/^/    /'
else
  echo -e "  vulnerabilidades confirmadas por prueba activa: ${GRN}0${NC}  ${DIM}(searchsploit.txt sigue siendo solo candidatos)"
fi
echo -e "${CYN}══════════════════════════════════════════════════${NC}"
