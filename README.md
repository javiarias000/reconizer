# reconizer

CLI de reconocimiento y **verificación activa** de vulnerabilidades para cualquier objetivo con una IP (labs, HTB, auditorías autorizadas, servicios propios).

## Filosofía: cero ambigüedad

El script **nunca emite suposiciones**. Un veredicto `VULNERABLE` / `NO_VULNERABLE` solo aparece cuando **se ejecutó una prueba real** contra el servicio y **se observó la respuesta**:

```
[VULNERABLE] :21 ftp (vsftpd 2.3.4) | prueba: login 'USER :)' + conexión a 6200 | evidencia: puerto 6200 ABIERTO tras login malicioso
[NO_VULNERABLE] :8080 http | prueba: GET /actuator/heapdump | evidencia: HTTP 404
```

- **searchsploit genera CANDIDATOS** (correlación versión↔exploit en base de datos) — nunca veredictos.
- El **PASO 4 (verificación activa)** prueba en vivo y solo él emite veredictos, siempre con: prueba ejecutada + evidencia observada.
- Los dominios **no se inventan**: se pasan con `--domain` y se comprueban (DNS + comparación HTTP con/sin cabecera `Host`).

## Flujo

| Paso | Qué hace | Qué afirma |
|---|---|---|
| 0 | ping + verificación DNS del `--domain` | solo hechos comprobados |
| 1 | nmap (`--quick`/`--all`/`--deep`/`--connect`) | puertos/servicios/versiones |
| 2 | headers HTTP + **prueba de vhost** con y sin `Host:` | VHOST CONFIRMADO solo si la respuesta cambia |
| 3 | searchsploit por versión | **CANDIDATOS**, no veredictos |
| 4 | **Verificación activa**: nmap NSE `vuln` + sondas por servicio | `VULNERABLE` / `NO_VULNERABLE` con evidencia |
| 5 | feroxbuster (`--fuzz`) | rutas encontradas |
| 6 | bitácora: `writeup.md`, `credentials.txt`, `errors.md`, `verificacion.txt`, `nmap_vuln.txt` | — |

## Sondas activas (v4)

- vsftpd 2.3.4 — baseline de 6200 **antes** del trigger (anti falso VULNERABLE), luego login `USER :)` y conexión a 6200
- ProFTPD mod_copy — `SITE CPFR` sin autenticar → 350
- Spring Boot — `GET /actuator/heapdump` y `/actuator/env` → 200
- Tomcat — `GET /manager/html` sin credenciales → 200
- WebDAV — `PROPFIND /` → 207 + `PUT` anónimo → 201/204
- FTP anónimo — login `anonymous` → 230 (HECHO probado)
- nmap NSE `vuln and not dos` sobre todos los puertos abiertos
- Servicios sin sonda: lo dicen explícitamente (nada de silencio)

## Uso

```bash
reconizer <IP> <nombre_maquina> [flags]

  --quick        top-1000 puertos
  --all          todos los puertos (default)
  --deep         -p- + -A (detección de OS)
  --connect      -sT (para localhost/WSL), sin perder -sV
  --fuzz         feroxbuster en puertos HTTP
  --skip-nmap    reutiliza nmap.txt previo
  --skip-vuln    solo candidatos, sin verificación activa
  --domain DOM   dominio a VERIFICAR contra la IP (no se inventa ninguno)
  --set-dir DIR  directorio base de bitácoras (persiste en ~/.config/reconizer.conf)
```

## Instalación

```bash
sudo cp reconizer.sh /usr/local/bin/reconizer && chmod +x /usr/local/bin/reconizer
```

Requisitos: `nmap`, `searchsploit` (exploitdb), `curl`; opcional `feroxbuster`.

## Historial de versiones

- **v1** — recon básico: nmap + sugerencias de vectores (modo tutor).
- **v2** — + searchsploit por versión, feroxbuster, bitácora persistente.
- **v3** — verificación ACTIVA con veredictos basados solo en pruebas ejecutadas; `--domain` con verificación DNS+HTTP; eliminadas todas las sugerencias genéricas.
- **v4** — hardening tras auditoría de código (10 fixes): esquema http/https correcto por servicio/puerto (anti falso NO_VULNERABLE), baseline pre-trigger del backdoor vsftpd (anti falso VULNERABLE), parseo de paréntesis anidados con bucle sed, awk NSE reescrito (solo cabeceras, exclusión case-insensitive), `tcp_open`/`tcp_send` con ip/puerto/payload como argv, `--connect` sin matar `-sV`, validación de IP/nombre, servicios sin sonda explícitos, trap con PID exacto anti-procesos huérfanos.
- **v5** — expansión de cobertura y pruebas: sondas SMB/MySQL/Redis/SNMP con binarios reales (smbclient sesión nula, mysql root sin password, redis PING/CONFIG, snmpget community public), scripts NSE dedicados por servicio (`nse_run` reutilizable), `--udp` (top-20, separa `open` confirmado de `open|filtered` ambiguo), `--nuclei` (JSONL con template-id/matched-at como evidencia), `--shots` (gowitness), fuzzing adaptativo al `Server:` detectado, searchsploit paralelo (×4), diff entre corridas, `hallazgos.md` auto-regenerado (writeup.md intacto), hardening de `report()` contra newlines.

## Aviso

Solo usar contra objetivos autorizados (labs, máquinas propias, auditorías con permiso).