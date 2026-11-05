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

# http_scheme SVC PORT -> "http" o "https". Antes el script usaba "http://" a lo ciego
# en TODAS las sondas: contra un puerto TLS (ssl/http, 443, 8443...) eso falla silenciosamente
# (reset/empty reply) y el resultado era un falso NO_VULNERABLE por protocolo equivocado, no
# por ausencia real del problema.
http_scheme() {
  case "$1" in *ssl*|https) echo https; return ;; esac
  case "$2" in 443|8443|9443) echo https ;; *) echo http ;; esac
}

# limpieza: si Ctrl-C mata el script, no deja nmap/feroxbuster huerfanos en background
_CPID=""
cleanup() { [ -n "$_CPID" ] && kill "$_CPID" 2>/dev/null; exit 130; }
trap cleanup INT TERM

# step_run "<label>" "<comando>" — spinner + cronometro en vivo; al terminar "[+] label (Ns)"
step_run() {
  local label="$1"; local cmd="$2"; local i=0
  bash -c "$cmd" &
  local pid=$!
  _CPID=$pid
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r    \033[36m%s\033[0m \033[2m%s...\033[0m  \033[33m%ds\033[0m   " "${SPIN:i%10:1}" "$label" "$i"
    sleep 1; i=$((i+1))
  done
  wait "$pid"; local rc=$?
  _CPID=""
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
  --fuzz         feroxbuster en cada puerto HTTP (wordlist/extensiones se adaptan al Server: detectado)
  --udp          nmap -sU top-puertos (NTP/SNMP/DNS/TFTP/...) ademas del escaneo TCP
  --nuclei       corre nuclei (cves/exposures/default-logins) contra cada puerto HTTP (PASO 4c)
  --shots        screenshot de cada puerto HTTP con gowitness (PASO 2c)
  --skip-nmap    no lanzar nmap: reusa <bitacora>/nmap.txt existente
  --skip-vuln    no lanzar la verificacion activa (PASO 4)
  --domain DOM   dominio a verificar contra la IP (el script NO inventa dominios:
                  comprueba DNS + respuesta HTTP con cabecera Host antes de afirmar nada)
  --set-dir DIR  cambia el directorio base de las auditorias (se recuerda)
  --help         esta ayuda

Las herramientas opcionales (--udp, --nuclei, --shots, --fuzz) se saltan con un aviso
claro si el binario no esta instalado: nunca fallan en silencio, nunca inventan resultado.

EJEMPLOS:
  reconizer 10.10.10.5 army --quick
  reconizer 10.10.10.5 army --all --fuzz --udp
  reconizer 10.10.10.5 army --skip-nmap
  reconizer 10.129.145.124 stream --domain htb-airport.htb --nuclei --shots
EOF
}

# ---------- parseo ----------
IP="${1:-}"; MAQ="${2:-}"
if [ "$IP" = "--help" ] || [ "$IP" = "-h" ]; then usage; exit 0; fi
MODE=all; FUZZ=0; SKIPNMAP=0; SKIPVULN=0; CONNECT=0; NEWDIR=0; SETDIR=""; DOMAIN=""
UDP=0; NUCLEI=0; SHOTS=0
if [ -z "$IP" ] || [ -z "$MAQ" ]; then usage; exit 1; fi
# saneo basico: $IP se interpola en comandos bash -c mas abajo (nmap/curl/tcp_*).
# Sin esto, un typo o copy-paste raro en la IP se ejecuta como shell.
if ! [[ "$IP" =~ ^[A-Za-z0-9.:-]+$ ]]; then
  fail "host/IP con caracteres invalidos: '$IP'"; exit 1
fi
if ! [[ "$MAQ" =~ ^[A-Za-z0-9._-]+$ ]]; then
  fail "nombre de maquina invalido (sin '/' ni espacios): '$MAQ'"; exit 1
fi
shift 2
while [ $# -gt 0 ]; do
  case "$1" in
    --all)       MODE=all; shift ;;
    --quick)     MODE=quick; shift ;;
    --deep)      MODE=deep; shift ;;
    --connect)   CONNECT=1; shift ;;
    --fuzz)      FUZZ=1; shift ;;
    --udp)       UDP=1; shift ;;
    --nuclei)    NUCLEI=1; shift ;;
    --shots)     SHOTS=1; shift ;;
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
  # -sT y -sV NO son excluyentes en nmap (tipo de scan vs deteccion de version): antes este sed
  # borraba -sV por error, dejando VER vacio en PASO 3/4 y matando searchsploit entero con --connect.
  [ $CONNECT -eq 1 ] && OPTS="-sT $OPTS"
  # guardo el resultado anterior ANTES de pisarlo, para poder mostrar que cambio desde la ultima corrida
  [ -f "$NMAP_OUT" ] && cp "$NMAP_OUT" "$NMAP_OUT.prev"
  step_run "nmap escaneando" "nmap $OPTS -oN '$NMAP_OUT' '$IP'"
fi

SERVICIOS=$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT")
NPORT=$(echo "$SERVICIOS" | grep -c .)

# diff contra la corrida anterior del MISMO host (solo si hubo scan fresco y existe un .prev real)
if [ -f "$NMAP_OUT.prev" ]; then
  PREV_SVC=$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT.prev")
  ADDED=$(comm -13 <(echo "$PREV_SVC" | sort) <(echo "$SERVICIOS" | sort))
  REMOVED=$(comm -23 <(echo "$PREV_SVC" | sort) <(echo "$SERVICIOS" | sort))
  if [ -n "$ADDED" ] || [ -n "$REMOVED" ]; then
    say "PASO 1 diff: cambios desde la ultima corrida contra $IP"
    [ -n "$ADDED" ]   && { echo -e "    ${GRN}+ nuevo:${NC}"; echo "$ADDED" | sed 's/^/      /'; }
    [ -n "$REMOVED" ] && { echo -e "    ${RED}- ya no aparece:${NC}"; echo "$REMOVED" | sed 's/^/      /'; }
  else
    say "PASO 1 diff: sin cambios de puertos/servicios desde la ultima corrida"
  fi
fi
echo
say "servicios: ${GRN}${NPORT} puertos abiertos${NC}"
echo "$SERVICIOS" | sed 's/^/    /'

# ---------- PASO 1b: UDP (--udp) ----------
# UDP sin respuesta es intrinsecamente ambiguo en nmap ("open|filtered": no se puede distinguir
# puerto abierto sin servicio que responda de un firewall que dropea el paquete en silencio).
# El script NO colapsa esa ambiguedad en un "abierto": muestra exactamente lo que nmap reporto.
if [ $UDP -eq 1 ]; then
  echo
  UDP_OUT="$BITACORA/nmap_udp.txt"
  step_run "nmap UDP (top 20 puertos: dns/snmp/ntp/tftp/...)" "nmap -sU -Pn --top-ports 20 -T4 -oN '$UDP_OUT' '$IP' >/dev/null 2>&1"
  UDP_CONFIRMED=$(grep -E '^[0-9]+/udp\s+open\s' "$UDP_OUT" | grep -v 'open|filtered')
  UDP_AMBIGUO=$(grep -E '^[0-9]+/udp\s+open\|filtered' "$UDP_OUT")
  if [ -n "$UDP_CONFIRMED" ]; then
    say "UDP: puertos ABIERTOS confirmados (respondieron) ${DIM}-> $UDP_OUT${NC}"
    echo "$UDP_CONFIRMED" | sed 's/^/    /'
  fi
  if [ -n "$UDP_AMBIGUO" ]; then
    warn "UDP: puertos open|filtered (SIN respuesta, no se afirma que esten abiertos; puede ser firewall) ${DIM}-> $UDP_OUT${NC}"
    echo "$UDP_AMBIGUO" | sed 's/^/    /'
  fi
  [ -z "$UDP_CONFIRMED" ] && [ -z "$UDP_AMBIGUO" ] && say "UDP: nada abierto ni ambiguo en el top-20 (prueba ejecutada, resultado negativo)"
  # la prueba ACTIVA de SNMP (comunidad 'public') va en PASO 4, junto al resto de veredictos
  # (aqui en PASO 1b todavia no existe report()/VERIF_LOG, y debe respetar --skip-vuln)
fi

# ---------- PASO 2: recon HTTP (solo headers clave) ----------
RAW_NMAP=$(cat "$NMAP_OUT")
PORTS_HTTP=$( { grep -E '^[0-9]+/tcp\s+open\s+http' "$NMAP_OUT" | cut -d/ -f1
  echo "$RAW_NMAP" | grep -iE 'uvicorn|nginx|apache|tomcat|jetty|httpd|gunicorn' | grep -E '^[0-9]+/tcp\s+open' | cut -d/ -f1
} | sort -u | grep -v '^$' || true )
REDIRECT_DOM=""
for P in $PORTS_HTTP; do
  echo
  SCH=$(http_scheme "$(echo "$SERVICIOS" | grep "^$P/tcp")" "$P")
  say "PASO 2: $SCH en :$P  ${DIM}(headers clave)${NC}"
  # una sola peticion real (antes se repetia la misma al tiro); se guarda cruda para que PASO 5
  # (--fuzz) elija extensiones/wordlist en base a ESTA evidencia, sin inventar ni repetir la red
  HDRS_OUT="$BITACORA/http_headers_$P.txt"
  curl -sik --max-time 10 "$SCH://$IP:$P/" > "$HDRS_OUT" 2>/dev/null
  grep -iE '^(HTTP/|server:|location:|x-powered|content-type:)' "$HDRS_OUT" | head -6 | sed 's/^/    /'
  LOC=$(grep -i '^location:' "$HDRS_OUT" | tr -d '\r' | awk '{print $2}')
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
    SCH=$(http_scheme "$(echo "$SERVICIOS" | grep "^$P/tcp")" "$P")
    BASE_RSP=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}:%{size_download}' "$SCH://$IP:$P/")
    DOM_RSP=$(curl -sk --max-time 8 -H "Host: $DOMAIN" -o /dev/null -w '%{http_code}:%{size_download}' "$SCH://$IP:$P/")
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

# ---------- PASO 2c: screenshots (--shots) ----------
if [ $SHOTS -eq 1 ]; then
  echo
  if ! command -v gowitness >/dev/null; then
    warn "gowitness no instalado: screenshots se omiten (ver https://github.com/sensepost/gowitness)"
  elif [ -z "$PORTS_HTTP" ]; then
    say "PASO 2c: sin puertos HTTP detectados, nada que capturar"
  else
    SHOTS_DIR="$BITACORA/screenshots"; mkdir -p "$SHOTS_DIR"
    for P in $PORTS_HTTP; do
      SCH=$(http_scheme "$(echo "$SERVICIOS" | grep "^$P/tcp")" "$P")
      step_run "screenshot $SCH://:$P" "gowitness single --url '$SCH://$IP:$P/' --write-jsonl -d '$SHOTS_DIR' >/dev/null 2>&1"
    done
    NSHOTS=$(find "$SHOTS_DIR" -name '*.png' 2>/dev/null | wc -l)
    ok "PASO 2c: ${NSHOTS} screenshot(s) guardados  ${DIM}-> $SHOTS_DIR${NC}"
  fi
fi

# ---------- PASO 3: searchsploit (solo genera CANDIDATOS, no veredictos) ----------
echo
say "PASO 3: searchsploit por cada version  ${DIM}(CANDIDATOS, no veredictos)${NC}"
SEARCH_LOG="$BITACORA/searchsploit.txt"
SSTART=$(date +%s)
: > "$SEARCH_LOG"
# paralelizado con tope de jobs: cada puerto escribe a SU PROPIO archivo temporal (nunca al
# mismo SEARCH_LOG al mismo tiempo que otro job -> sin interleaving/corrupcion), y al final se
# concatenan en orden de puerto. Asi no reintroducimos la race condition que evitamos en 4a/4b.
SS_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/reconizer_ss.XXXXXX")
SS_MAXJOBS=4
ss_job() {
  local port="$1" svc="$2" ver="$3" tag="$4"
  {
    echo "------------------------------------------------"
    echo "# puerto $port ($svc): $ver"
    searchsploit "$ver" 2>/dev/null | head -10
  } > "$SS_TMPDIR/block_$tag.txt"
  local nexp
  nexp=$(searchsploit --id "$ver" 2>/dev/null | grep -cE '\|')
  echo -e "    ${YLW}[$port/$svc]${NC} $ver  ${DIM}-> ${nexp} exploits candidatos${NC}" > "$SS_TMPDIR/line_$tag.txt"
}
TAG=0
while IFS= read -r line; do
  PORT=$(echo "$line" | cut -d/ -f1)
  SVC=$(echo "$line" | awk '{print $3}')
  # s/([^)]*)//g sola dejaba un ")" suelto con parentesis anidados tipo "((Ubuntu))" (comun en
  # nmap). El bucle :a;...;ta repite hasta que no queden pares, y el sed final limpia sobrantes.
  VER=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' \
    | sed -E ':a; s/\([^()]*\)//g; ta' \
    | sed 's/[()]//g; s/  */ /g; s/^ *//; s/ *$//')
  [ -z "$VER" ] && continue
  TAG=$((TAG+1))
  printf -v TAGP '%04d' "$TAG"   # zero-pad para que el glob posterior respete el orden
  ss_job "$PORT" "$SVC" "$VER" "$TAGP" &
  while [ "$(jobs -r -p | wc -l)" -ge "$SS_MAXJOBS" ]; do wait -n 2>/dev/null || sleep 0.2; done
done <<< "$(grep -E '^[0-9]+/tcp\s+open' "$NMAP_OUT")"
wait
for f in "$SS_TMPDIR"/block_*.txt; do [ -f "$f" ] && cat "$f" >> "$SEARCH_LOG"; done
for f in "$SS_TMPDIR"/line_*.txt; do [ -f "$f" ] && cat "$f"; done
rm -rf "$SS_TMPDIR"
SDUR=$(( $(date +%s) - SSTART ))
ok "searchsploit  ${DIM}(${SDUR}s, hasta ${SS_MAXJOBS} en paralelo)${NC} -> $SEARCH_LOG"
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
  # endurecido tras probarlo: si "ev" trae un salto de linea (una herramienta externa devolviendo
  # algo multilinea donde se esperaba un escalar) NO debe partir el registro en VERIF_LOG, o los
  # conteos por grep -c de PASO 6/hallazgos.md quedan mal. Se colapsa a una sola linea siempre.
  report() {
    local state="$1" tgt="$2" t="$3"
    local ev; ev=$(printf '%s' "$4" | tr '\n' ' ' | sed 's/  */ /g; s/ *$//')
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
  # ip/port/payload van como argv al sub-bash (no interpolados en el string del comando):
  # asi una comilla o metacaracter en el valor no puede romper ni inyectar en el comando.
  tcp_open() {
    local ip="$1" port="$2" t="${3:-3}"
    timeout "$t" bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$ip" "$port" 2>/dev/null
  }
  # util: envia payload crudo por TCP y devuelve la respuesta
  tcp_send() {
    local ip="$1" port="$2" payload="$3" t="${4:-6}"
    timeout "$t" bash -c 'exec 3<>"/dev/tcp/$0/$1"; printf "%b" "$2" >&3; cat <&3' "$ip" "$port" "$payload" 2>/dev/null
  }

  # nse_vuln_findings <archivo> -> nombres de script/CVE que el NSE marco VULNERABLE en ese archivo.
  # Logica compartida por 4a y por nse_run (4b): cur solo se toma de una cabecera "| algo:" SIN
  # indentacion extra (evita pisar el nombre con lineas de detalle como "|   State:"), y la
  # comparacion vulnerable/not-vulnerable es case-insensitive real (nmap escribe "NOT VULNERABLE"
  # en mayusculas; un regex que solo variaba la 1ra letra dejaba pasar falsos VULNERABLE).
  nse_vuln_findings() {
    awk '
      /^[0-9]+\/tcp/ { cur=""; next }
      /^\|_?[ ][^ ]/ {
        line=$0; sub(/^\|_?/,"",line); sub(/^ /,"",line)
        if (line ~ /^[A-Za-z0-9_.-]+:[ ]*$/) { cur=line; sub(/:[ ]*$/,"",cur); next }
      }
      tolower($0) ~ /vulnerable/ && tolower($0) !~ /not vulnerable/ && cur != "" { print cur }
    ' "$1" | sort -u
  }

  # nse_run PORT SCRIPTS TAG LABEL -> corre esos scripts NSE de verdad contra ese puerto,
  # guarda el .txt crudo, reporta cada VULNERABLE real y un resumen de hallazgos informativos
  # (shares, usuarios, banners...) con el archivo como evidencia citable.
  nse_run() {
    local port="$1" scripts="$2" tag="$3" label="$4"
    local out="$BITACORA/nse_${tag}_${port}.txt"
    step_run "$label" "nmap -Pn -sV --script '$scripts' -p '$port' -oN '$out' '$IP' >/dev/null 2>&1"
    nse_vuln_findings "$out" | while read -r v; do
      report VULNERABLE ":$port ($tag NSE: $v)" "nmap --script '$scripts' -p $port" "script NSE reporta VULNERABLE (detalle: $(basename "$out"))"
    done
    # lineas con contenido real (no cabeceras de puerto ni separadores) -> evidencia informativa
    local info
    info=$(grep -E '^\|' "$out" 2>/dev/null | grep -viE 'VULNERABLE|not vulnerable' | head -5)
    if [ -n "$info" ]; then
      report HECHO ":$port ($tag NSE)" "nmap --script '$scripts' -p $port" "salida real (primeras lineas, completo en $(basename "$out")): $(echo "$info" | tr '\n' ' ' | sed 's/  */ /g')"
    fi
  }

  # 4a) nmap NSE: scripts de vulnerabilidad sobre TODOS los puertos abiertos (prueba activa real)
  OPENPORTS=$(echo "$SERVICIOS" | cut -d/ -f1 | paste -sd, -)
  NSE_OUT="$BITACORA/nmap_vuln.txt"
  step_run "nmap NSE vuln scripts (puertos: $OPENPORTS)" "nmap -Pn -sV --script 'vuln and not dos' -p '$OPENPORTS' -oN '$NSE_OUT' '$IP' >/dev/null 2>&1"
  nse_vuln_findings "$NSE_OUT" | while read -r v; do
    report VULNERABLE "$IP (NSE: $v)" "nmap --script 'vuln and not dos' contra puertos abiertos" "script NSE reporta VULNERABLE (detalle: nmap_vuln.txt)"
  done
  grep -q 'VULNERABLE' "$NSE_OUT" 2>/dev/null || say "NSE: ningun script reporto VULNERABLE (pruebas ejecutadas, todas negativas)"

  # 4b) sondas especificas por servicio: cada una ENVIA algo y OBSERVA la respuesta
  # chequeo de binarios UNA sola vez (no por puerto) para no repetir el mismo warning N veces
  HAVE_SMBCLIENT=0; command -v smbclient >/dev/null && HAVE_SMBCLIENT=1 || warn "smbclient no instalado: sondas SMB se omiten (apt install smbclient)"
  HAVE_MYSQL=0;     command -v mysql     >/dev/null && HAVE_MYSQL=1     || warn "cliente mysql no instalado: sonda MySQL se omite (apt install mysql-client)"
  HAVE_REDIS=0;     command -v redis-cli >/dev/null && HAVE_REDIS=1     || warn "redis-cli no instalado: sonda Redis se omite (apt install redis-tools)"

  while IFS= read -r line; do
    PORT=$(echo "$line" | cut -d/ -f1)
    SVC=$(echo "$line" | awk '{print $3}')
    # s/([^)]*)//g sola dejaba un ")" suelto con parentesis anidados tipo "((Ubuntu))" (comun en
    # nmap). El bucle :a;...;ta repite hasta que no queden pares, y el sed final limpia sobrantes.
    VER=$(echo "$line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' \
      | sed -E ':a; s/\([^()]*\)//g; ta' \
      | sed 's/[()]//g; s/  */ /g; s/^ *//; s/ *$//')

    case "$SVC" in
    ftp)
      # vsftpd 2.3.4: el backdoor abre 6200 tras un login malicioso. Se prueba de verdad.
      if echo "$VER" | grep -q 'vsftpd 2\.3\.4'; then
        # baseline ANTES del trigger: si 6200 ya estaba abierto por otra razon, el chequeo
        # posterior no prueba nada (antes no habia baseline -> falso VULNERABLE posible)
        if tcp_open "$IP" 6200 1; then
          report HECHO ":$PORT ftp (vsftpd 2.3.4)" "chequeo baseline de 6200 (previo al trigger)" "6200 YA estaba abierto antes del login: prueba no concluyente, revisar manualmente"
        else
          tcp_send "$IP" "$PORT" 'USER t:)\r\nPASS x\r\nQUIT\r\n' 6 >/dev/null 2>&1; sleep 3
          if tcp_open "$IP" 6200 2; then
            report VULNERABLE ":$PORT ftp (vsftpd 2.3.4)" "baseline 6200 cerrado + login 'USER t:)' + intento de conexion a 6200" "puerto 6200 ABIERTO tras el login malicioso (cerrado antes): backdoor confirmado"
          else
            report NO_VULNERABLE ":$PORT ftp (vsftpd 2.3.4)" "baseline 6200 cerrado + login 'USER t:)' + intento de conexion a 6200" "6200 sigue cerrado: el backdoor no se activo"
          fi
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
    microsoft-ds|netbios-ssn)
      # scripts NSE de verdad (no la categoria 'vuln' generica de 4a, que no cubre enum/discovery)
      nse_run "$PORT" 'smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067' smb "nmap scripts SMB :$PORT"
      # sesion nula real con smbclient: hecho probado, no inferido del banner
      if [ $HAVE_SMBCLIENT -eq 1 ]; then
        RESP=$(timeout 10 smbclient -L "//$IP" -N -m SMB2 2>&1)
        if echo "$RESP" | grep -qiE 'Sharename|Disk\s*\|'; then
          report HECHO ":$PORT smb" "smbclient -L //$IP -N (sesion nula)" "listado de shares obtenido sin credenciales"
        else
          report NO_VULNERABLE ":$PORT smb" "smbclient -L //$IP -N (sesion nula)" "sin listado de shares (respuesta: $(echo "$RESP" | head -1))"
        fi
      fi
      ;;
    mysql)
      nse_run "$PORT" 'mysql-info,mysql-empty-password,mysql-databases,mysql-users' mysql "nmap scripts MySQL :$PORT"
      if [ $HAVE_MYSQL -eq 1 ]; then
        RESP=$(timeout 8 mysql -h "$IP" -P "$PORT" -u root --connect-timeout=5 -e 'select 1' 2>&1)
        if echo "$RESP" | grep -q '^1$'; then
          report VULNERABLE ":$PORT mysql" "login 'root' sin password (mysql -u root -e 'select 1')" "login exitoso sin credenciales"
        else
          report NO_VULNERABLE ":$PORT mysql" "login 'root' sin password" "login rechazado (respuesta: $(echo "$RESP" | head -1))"
        fi
      fi
      ;;
    redis)
      if [ $HAVE_REDIS -eq 1 ]; then
        RESP=$(timeout 8 redis-cli -h "$IP" -p "$PORT" --no-raw ping 2>&1)
        if echo "$RESP" | grep -q 'PONG'; then
          report VULNERABLE ":$PORT redis" "redis-cli -h $IP ping (sin auth)" "respuesta PONG sin autenticacion: acceso no autenticado confirmado"
          CFG=$(timeout 8 redis-cli -h "$IP" -p "$PORT" --no-raw config get dir 2>&1 | tail -1)
          [ -n "$CFG" ] && report HECHO ":$PORT redis" "redis-cli config get dir (tras ping sin auth)" "dir configurado: $CFG"
        else
          report NO_VULNERABLE ":$PORT redis" "redis-cli -h $IP ping (sin auth)" "sin PONG (respuesta: $(echo "$RESP" | head -1))"
        fi
      fi
      ;;
    http|https|http-alt|http-proxy)
      SCH=$(http_scheme "$line" "$PORT")
      # nuclei (--nuclei): motor adicional de verificacion activa con templates mas frescos
      # que la categoria 'vuln' de nmap. Cada hallazgo que imprime viene de una petición real
      # con matcher cumplido, asi que se reporta VULNERABLE con la evidencia tal cual la dio.
      if [ $NUCLEI -eq 1 ]; then
        if command -v nuclei >/dev/null; then
          NUC_OUT="$BITACORA/nuclei_${PORT}.jsonl"
          step_run "nuclei :$PORT ($SCH)" "nuclei -u '$SCH://$IP:$PORT' -t cves/,exposures/,default-logins/ -silent -jsonl-export '$NUC_OUT' >/dev/null 2>&1"
          if [ -s "$NUC_OUT" ]; then
            while IFS= read -r nline; do
              NID=$(echo "$nline" | grep -oE '"template-id":"[^"]*"' | head -1 | cut -d'"' -f4)
              NMATCHED=$(echo "$nline" | grep -oE '"matched-at":"[^"]*"' | head -1 | cut -d'"' -f4)
              [ -z "$NID" ] && NID="(sin template-id, ver $NUC_OUT)"
              report VULNERABLE ":$PORT $SCH (nuclei: $NID)" "nuclei -t cves/,exposures/,default-logins/" "matcher cumplido en $NMATCHED (detalle: $(basename "$NUC_OUT"))"
            done < "$NUC_OUT"
          else
            report NO_VULNERABLE ":$PORT $SCH (nuclei)" "nuclei -t cves/,exposures/,default-logins/" "ningun template dio match"
          fi
        else
          warn "nuclei no instalado: sonda nuclei se omite en :$PORT (ver https://github.com/projectdiscovery/nuclei)"
        fi
      fi
      # Spring Boot actuator expuesto
      for path in /actuator/heapdump /actuator/env; do
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "$SCH://$IP:$PORT$path")
        if [ "$code" = "200" ]; then
          report VULNERABLE ":$PORT $SCH" "GET $path" "HTTP 200: actuator expuesto"
        else
          report NO_VULNERABLE ":$PORT $SCH" "GET $path" "HTTP $code"
        fi
      done
      # Tomcat manager sin credenciales
      code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "$SCH://$IP:$PORT/manager/html")
      if [ "$code" = "200" ]; then
        report VULNERABLE ":$PORT $SCH (tomcat)" "GET /manager/html sin credenciales" "HTTP 200: manager accesible"
      else
        report NO_VULNERABLE ":$PORT $SCH (tomcat)" "GET /manager/html sin credenciales" "HTTP $code"
      fi
      # WebDAV: PROPFIND y PUT anonimo (la escritura es lo explotable)
      code=$(curl -sk -X PROPFIND -H 'Depth: 0' -o /dev/null -w '%{http_code}' --max-time 8 "$SCH://$IP:$PORT/")
      if [ "$code" = "207" ]; then
        PUTCODE=$(curl -sk -X PUT -d 'davtest' -o /dev/null -w '%{http_code}' --max-time 8 "$SCH://$IP:$PORT/davtest.txt")
        if [ "$PUTCODE" = "201" ] || [ "$PUTCODE" = "204" ]; then
          report VULNERABLE ":$PORT $SCH" "PROPFIND / (207) + PUT /davtest.txt" "HTTP $PUTCODE: WebDAV con escritura anonima"
        else
          report HECHO ":$PORT $SCH" "PROPFIND / (207) + PUT /davtest.txt" "WebDAV activo pero PUT anonimo devolvio $PUTCODE (sin escritura)"
        fi
      fi
      ;;
    *)
      echo -e "    ${DIM}sin sonda automatica para '$SVC' (:$PORT) — no se ejecuto ninguna prueba, revisar manualmente${NC}"
      ;;
    esac
  done <<< "$SERVICIOS"

  # 4c) SNMP (solo si --udp confirmo 161/udp open de verdad, no open|filtered): comunidad 'public'
  UDP_OUT="$BITACORA/nmap_udp.txt"
  if [ $UDP -eq 1 ] && [ -f "$UDP_OUT" ] && grep -qE '^161/udp\s+open\s' "$UDP_OUT" && ! grep -qE '^161/udp\s+open\|filtered' "$UDP_OUT"; then
    if command -v snmpget >/dev/null; then
      SNMP_RESP=$(timeout 6 snmpget -v2c -c public -r 1 -t 3 "$IP" 1.3.6.1.2.1.1.1.0 2>&1)
      if echo "$SNMP_RESP" | grep -qiE 'STRING|OID|Hex-STRING'; then
        report VULNERABLE ":161/udp snmp" "snmpget -v2c -c public sysDescr (1.3.6.1.2.1.1.1.0)" "respondio sin credenciales reales: $(echo "$SNMP_RESP" | head -1)"
      else
        report NO_VULNERABLE ":161/udp snmp" "snmpget -v2c -c public sysDescr" "sin respuesta valida (community 'public' rechazada o timeout)"
      fi
    else
      warn "snmpget no instalado: sonda SNMP se omite (apt install snmp)"
    fi
  fi

  NCONF=$(grep -c '^\[VULNERABLE\]' "$VERIF_LOG")
  ok "verificacion: ${GRN}${NCONF} vulnerabilidades CONFIRMADAS por prueba activa${NC} -> $VERIF_LOG"
fi

# ---------- PASO 5: fuzzing ----------
if [ $FUZZ -eq 1 ]; then
  echo
  if ! command -v feroxbuster >/dev/null; then
    warn "feroxbuster no instalado (sudo apt install feroxbuster) — saltando"
  else
    # wordlist: la de siempre si existe; si no, probar un par de alternativas comunes de Kali
    # en vez de fallar en seco con un path que puede no existir segun la instalacion.
    WORDLIST=""
    for wl in /usr/share/seclists/Discovery/Web-Content/common.txt \
              /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
              /usr/share/wordlists/dirb/common.txt; do
      [ -f "$wl" ] && { WORDLIST="$wl"; break; }
    done
    if [ -z "$WORDLIST" ]; then
      warn "ninguna wordlist conocida encontrada (seclists/dirb) — PASO 5 se omite, instalar seclists"
    else
      for P in $PORTS_HTTP; do
        SCH=$(http_scheme "$(echo "$SERVICIOS" | grep "^$P/tcp")" "$P")
        # extensiones: del header REAL que ya guardo PASO 2 para este puerto (no se inventa nada;
        # si no hay evidencia de tecnologia, se fuzz sin -x en vez de asumir una pila al azar)
        EXT=""
        HDRS_OUT="$BITACORA/http_headers_$P.txt"
        if [ -f "$HDRS_OUT" ]; then
          if grep -qi 'X-Powered-By:.*PHP\|\.php' "$HDRS_OUT"; then EXT="php"
          elif grep -qi 'X-Powered-By:.*ASP\|Server:.*IIS' "$HDRS_OUT"; then EXT="asp,aspx"
          elif grep -qi 'Server:.*Jetty\|Server:.*Tomcat' "$HDRS_OUT"; then EXT="jsp,do,action"
          fi
        fi
        EXTOPT=""; [ -n "$EXT" ] && EXTOPT="-x $EXT"
        say "PASO 5: feroxbuster en $SCH://:$P  ${DIM}(wordlist: $(basename "$WORDLIST")${EXT:+, ext: $EXT})${NC}"
        FUZZOUT="$BITACORA/ferox_$P.txt"
        step_run "fuzz :$P" "feroxbuster -u '$SCH://$IP:$P/' -w '$WORDLIST' $EXTOPT -k -S 178 -n -d 1 >'$FUZZOUT' 2>&1"
        NF=$(grep -cE '^\s*(200|201|204|301|302|307|401|403|405|500)' "$FUZZOUT" 2>/dev/null || echo 0)
        ok "rutas interesantes en :$P: ${NF}  ${DIM}->$FUZZOUT${NC}"
        grep -E '^\s*(200|201|204|301|302|307|401|403|405|500)' "$FUZZOUT" 2>/dev/null | head -10 | sed 's/^/      /'
      done
    fi
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

Hallazgos automaticos de cada corrida: ver hallazgos.md (ese archivo se regenera solo, tus
notas de aqui en writeup.md NO se tocan).

## Fase 1 -
WEOF
[ -f "$BITACORA/credentials.txt" ] || echo "=== CREDENCIALES - $MAQ ($IP) ===" > "$BITACORA/credentials.txt"
[ -f "$BITACORA/errors.md" ] || printf "# errors.md - $MAQ\n# error -> causa -> correccion -> leccion\n" > "$BITACORA/errors.md"

# hallazgos.md SI se regenera siempre (writeup.md no, para no pisar notas manuales del usuario)
HALLAZGOS_MD="$BITACORA/hallazgos.md"
{
  echo "# Hallazgos automaticos - $MAQ ($IP)"
  echo
  echo "_Regenerado por reconizer el $(date '+%Y-%m-%d %H:%M'). Archivo auto-generado: no editar,_"
  echo "_se sobreescribe en cada corrida. Las notas propias van en writeup.md._"
  echo
  if [ -f "$VERIF_LOG" ]; then
    NV=$(grep -c '^\[VULNERABLE\]' "$VERIF_LOG")
    echo "## VULNERABLE confirmados por prueba activa ($NV)"
    if [ "$NV" -gt 0 ]; then
      grep '^\[VULNERABLE\]' "$VERIF_LOG" | sed 's/^\[VULNERABLE\] /- /'
    else
      echo "_ninguno (pruebas ejecutadas, todas negativas)_"
    fi
    echo
    NH=$(grep -c '^\[HECHO\]' "$VERIF_LOG")
    echo "## HECHO - observado y probado, no es veredicto de CVE ($NH)"
    if [ "$NH" -gt 0 ]; then
      grep '^\[HECHO\]' "$VERIF_LOG" | sed 's/^\[HECHO\] /- /'
    else
      echo "_ninguno_"
    fi
  else
    echo "_PASO 4 no se ejecuto (--skip-vuln): sin veredictos en esta corrida._"
  fi
  echo
  echo "## Candidatos de searchsploit (CORRELACION version/exploit, sin confirmar activamente)"
  echo "Detalle completo en \`searchsploit.txt\`. Un candidato aqui NO implica que sea explotable:"
  echo "solo los items de la seccion VULNERABLE arriba fueron probados contra el objetivo."
} > "$HALLAZGOS_MD"

ok "writeup.md / hallazgos.md / credentials.txt / errors.md listos"

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
