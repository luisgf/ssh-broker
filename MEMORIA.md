# Memoria Técnica del Proyecto: SSH Broker

**Autor:** Luis Gonzalez Fernandez  
**Periodo de desarrollo:** 3–9 de junio de 2026  
**Versión final documentada:** v1.10.0  
**Repositorio:** github.com/luisgf/ssh-broker

---

## 1. Resumen ejecutivo

SSH Broker es una infraestructura de acceso SSH diseñada específicamente para agentes de inteligencia artificial. Resuelve un problema de seguridad concreto: cuando un agente de IA necesita ejecutar comandos en servidores Linux, las soluciones existentes le entregan una clave SSH estática que puede ser exfiltrada mediante inyección de prompts o volcado de memoria. Una vez robada, esa clave funciona indefinidamente.

El proyecto implementa un broker intermediario que actúa como servidor MCP (Model Context Protocol): el agente nunca recibe ninguna credencial, solo el resultado de la ejecución. Por cada operación, el broker genera un par Ed25519 efímero en memoria, obtiene un certificado SSH firmado por una CA de corta duración, ejecuta el comando y descarta todo el material criptográfico al terminar. Si el proceso del broker fuera comprometido, un atacante solo encontraría claves con TTL expirado.

El sistema se ha construido en siete días, iterando desde un prototipo de binario único hasta una arquitectura de múltiples componentes con firewall de acciones de IA, aprobación humana en el ciclo, guardrails de comportamiento, grabación de sesiones y un log de auditoría criptográficamente encadenado.

---

## 2. Motivación y contexto

### 2.1 El problema de las credenciales estáticas

La combinación de agentes de IA y acceso SSH presenta una vulnerabilidad estructural que las herramientas existentes no resuelven adecuadamente:

- **Inyección de prompts:** un payload malicioso puede instruir al agente a imprimir su clave SSH "para depuración". Con una clave estática, el atacante tiene acceso permanente.
- **Volcado de memoria:** la clave vive en el proceso del agente o en un fichero de configuración accesible desde él.
- **Sin límite temporal:** una clave SSH robada no expira. No existe mecanismo nativo de revocación por TTL.

La solución no es añadir más controles sobre la clave existente, sino eliminar la clave del alcance del agente por completo.

### 2.2 Por qué un MCP propio

La alternativa obvia —`mcp-ssh-manager`, basado en la librería Node `ssh2` 1.17— no soporta autenticación de cliente SSH mediante certificados. Con clave + certificado en el agente SSH, `ssh2` presenta solo la clave pelada (`ED25519`, no `ED25519-CERT`), que el `sshd` rechaza. El broker se construyó en Go usando `golang.org/x/crypto/ssh`, que soporta certificados de cliente correctamente.

### 2.3 Referentes de producción

El threat model no es nuevo: Teleport publicó su *Agentic Identity Framework* en enero de 2026 cubriendo exactamente el mismo problema. La diferencia es operativa: Teleport requiere un cluster de control-plane, un proxy de grabación y una interfaz web. SSH Broker cubre el mismo nicho de seguridad como un conjunto de binarios Go sin dependencias externas de infraestructura.

---

## 3. Arquitectura

### 3.1 Componentes

El sistema se compone de seis binarios y dieciséis paquetes Go:

```
Agente de IA (Claude / OpenCode)
        │
        │ MCP stdio (local) │ MCP HTTP+Bearer (red)
        ▼                   ▼
  cmd/mcp-broker    cmd/mcp-broker-http   ← nunca tienen clave CA
        │  mismas 5 tools   │  valida JWT vía JWKS
        └─────────┬─────────┘
                  │ genera par Ed25519 efímero en RAM
                  │ HTTPS + mTLS
                  ▼
       cmd/control-plane   (opcional, aprobación + guardrails)
                  │ HTTPS + mTLS
                  ▼
           cmd/signer       ← única custodia de la clave CA
                  │
                  ▼
           Host SSH :22     ← cert válido 60–300s, force-command
```

**cmd/mcp-broker** — servidor MCP sobre stdio. Interfaz local para el agente. Sin autenticación de red: el aislamiento lo proporciona el proceso.

**cmd/mcp-broker-http** — servidor MCP sobre Streamable HTTP protegido con OAuth2/OIDC (RFC 9728 + Authorization Code + PKCE). Para despliegues multiusuario en red. La identidad OIDC del usuario se propaga al signer para RBAC por usuario final.

**cmd/signer** — servicio de firma externo (HTTPS+mTLS). Única custodia de la clave CA SSH. Implementa la política de emisión: RBAC por grupos, sudo NOPASSWD, PTY, command policy, firewall de acciones. Audit log propio encadenado.

**cmd/control-plane** — Policy Enforcement Point entre el broker y el signer. Orquesta la aprobación humana de comandos marcados como `require_approval` y los guardrails de comportamiento. No custodia la clave CA.

**cmd/broker** — frontend HTTP+mTLS alternativo para agentes que se autentican con certificado de cliente (one-shot).

**cmd/broker-ctl** — CLI de gestión: añadir/listar/eliminar hosts, recargar el signer, ver y verificar logs de auditoría, aprobar/denegar solicitudes.

### 3.2 Flujo de emisión de certificados

El invariante más importante del sistema: **la clave privada efímera nunca sale del broker**.

1. El broker genera un par Ed25519 en memoria (`ca.GenerateEphemeralKey()`).
2. Envía al signer solo la clave pública, junto con la intención: host, role, purpose, command, sudo?, pty?, end_user, end_user_groups.
3. El signer valida RBAC, resuelve la policy y construye los constraints del certificado: principal, source-address, TTL, force-command (one-shot), permit-pty.
4. El signer firma con `ca.BuildAndSign()` usando su clave CA privada y devuelve el certificado.
5. El broker abre la conexión SSH presentando `certSigner{priv, cert}`. El sshd verifica la firma CA, el principal, la ventana de validez y el source-address.
6. Se ejecuta el comando; el broker descarta priv y cert.

En modo externo (recomendado para producción), un broker comprometido no puede firmar certificados propios ni acceder a la política.

### 3.3 Paquetes internos

| Paquete | Responsabilidad |
|---|---|
| `internal/ca` | `GenerateEphemeralKey`, `BuildAndSign`, `LoadCAFromPEM` |
| `internal/signer` | Interfaz `Signer`, `Local`, `Remote`, `PolicyTable`, `CommandPolicy` |
| `internal/broker` | Engine (execute + sessions + audit), Config |
| `internal/ssh` | Dial multi-hop, ExecOnce, ShellSession (shell/pty) |
| `internal/recording` | Recorder ASCIIcast v2 (stdin/stdout/stderr con timestamps) |
| `internal/audit` | Log append-only firmado y encadenado Ed25519+SHA-256 |
| `internal/control` | Registry de aprobaciones, BehaviorTracker, notifiers |
| `internal/mcpserver` | Registro de tools MCP compartido entre frontends |
| `internal/oauth` | Verificador OIDC (go-oidc, JWKS con rotación) |
| `internal/auth` | ServerTLSConfig mTLS, ClientTLSConfig, CallerCN |

---

## 4. Características implementadas

### 4.1 Certificados SSH efímeros en memoria

El núcleo de la propuesta de valor. Cada operación —one-shot o apertura de sesión— genera un par Ed25519 nuevo. El par vive únicamente en la RAM del proceso broker durante la operación (segundos). Los certificados llevan:

- `ValidPrincipals`: principal del host (e.g. `host:web01`), mapeado en `AuthorizedPrincipalsFile` del sshd.
- `ValidBefore` / `ValidAfter`: TTL configurable, máximo 15 minutos por diseño de seguridad.
- `source-address`: IP de egreso del broker (o del bastión, en cadenas ProxyJump). El sshd rechaza conexiones desde cualquier otra IP.
- `force-command`: comando exacto a ejecutar (solo one-shot). Baked in the cert por la clave CA; inevadible aunque el broker sea comprometido.
- `permit-pty`: solo si el host lo tiene habilitado y se solicitó.
- `permit-port-forwarding`: solo en certs de bastión.

### 4.2 ProxyJump / cadenas de bastión

El broker resuelve la cadena de saltos (`Jump` por host) y genera un certificado independiente por cada hop. El cert del bastión lleva `permit-port-forwarding` y sin `force-command`; el del destino lleva `force-command` y sin `permit-port-forwarding`. El `source-address` del destino debe ser la IP de egreso del bastión, no del broker.

### 4.3 Elevación de privilegios (sudo NOPASSWD)

La autorización de sudo vive en el signer (`allow_sudo`, `allowed_sudo_users`). Un broker comprometido no puede elevar en hosts que no lo tengan habilitado.

- **One-shot:** el signer bakes `sudo -n [-u U] -- /bin/sh -c '<cmd>'` en el `force-command` del certificado.
- **Sesión exec:** el signer devuelve `ElevationPrefix`; el broker lo antepone a cada comando.
- **Sesión shell/pty:** el shell completo se lanza bajo sudo.

El `sudo_user` se valida con regex `^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}$` y contra la whitelist del host para prevenir inyección.

### 4.4 Sesiones persistentes (tres modos)

Las sesiones reutilizan la conexión SSH entre comandos. El certificado autentica la conexión, no cada comando (sin `force-command`).

- **exec**: cada comando aislado (`ExecOnce`). Separación stdout/stderr.
- **shell**: shell `/bin/sh` con estado persistente (cd, variables). Sin PTY. Protocolo de marcadores aleatorios para detección de fin de comando.
- **pty**: igual que shell pero con pseudo-terminal. Stdout y stderr mezclados. Necesario para programas que comprueban `isatty()`.

El `sessionManager` impone límites: 200 sesiones globales, 20 por caller (M2). El reaper cierra sesiones por idle TTL y vida máxima. La seguridad C1 verifica que el caller que ejecuta un comando o cierra una sesión es quien la abrió.

### 4.5 AI-action firewall: command policy

Más allá de controlar *quién* accede, el signer controla *qué se ejecuta*.

**Evaluación de reglas** (RE2, tiempo lineal): modo allowlist, denylist u off por host. Reglas configuradas por el operador en `signer.json`.

**Shell AST parsing (v1.9.2):** al activar `shell_parse: true`, el comando se parsea con `mvdan.cc/sh/v3/syntax` como gramática POSIX sh antes de evaluar las reglas. Cada `CallExpr` del AST se evalúa por separado, lo que evita bypasses como `ps aux && kill -9 1000` contra una allowlist de `^ps`. Los nodos peligrosos (`CmdSubst`, `ProcSubst`, `ArithmCmd`, redirects a archivo) se rechazan incondicionalmente.

**Dry-run:** `ssh_execute` acepta `dry_run: true` para previsualizar la decisión de política sin conectar ni ejecutar. Útil para que el agente compruebe si un comando sería permitido antes de cometerlo.

**Hosts con command_policy rechazan sesiones:** el comando no es verificable al firmar (llega después de la emisión del cert). Estos hosts solo admiten `ssh_execute` one-shot.

### 4.6 Aprobación humana en el ciclo

El control plane implementa un gate de aprobación asíncrono para comandos marcados con `require_approval`:

1. Broker → control plane → signer (sin cert si requiere aprobación).
2. Control plane crea solicitud, notifica out-of-band (log / webhook / Microsoft Teams).
3. Broker hace polling con `GET /v1/sign/result/{id}`.
4. Humano aprueba: `broker-ctl approval allow <id>`.
5. Siguiente poll re-firma con `approved=true` y devuelve el certificado. Una aprobación emite exactamente un certificado.

La aprobación es inevadible: el signer solo honra `approved=true` desde `trusted_forwarders` (el CN del control plane, pinned en `signer.json`). Un broker que intente saltarse el control plane y llamar al signer directamente no puede auto-aprobarse.

### 4.7 Guardrails de comportamiento

El control plane rastrea el comportamiento de cada agente y detecta desviaciones:

- **Pico de tasa:** más de `rate_limit_per_min` peticiones en una ventana de 1 minuto.
- **Host nuevo:** host que el agente nunca ha usado antes.
- **Comando nuevo:** primer token del comando fuera del histórico del agente.

El sujeto es la identidad OIDC del usuario final cuando está disponible, o el CN del broker. La primera petición de un sujeto establece la línea base (nunca se marca).

Modos: `off` (por defecto), `observe` (solo audita), `enforce` (anomalías escalan a aprobación; rate excedido → 429).

### 4.8 Notificaciones Microsoft Teams

El control plane puede enviar notificaciones de aprobación a un canal de Teams mediante Incoming Webhook. Dos formatos:

- **Adaptive Card v1.4** (formato `workflow`, recomendado): sobre de Power Automate.
- **MessageCard** (formato `messagecard`, legacy): para tenants sin Workflow.

La card incluye todos los metadatos relevantes (approval ID, host, comando, caller, usuario final, elevación, regla de policy) y un botón "View request" si se configura `approval_url_template`. La aprobación bidireccional desde Teams (botón Approve en la card) requiere un `cmd/approval-bridge` pendiente de implementación.

### 4.9 RBAC por grupos

Dos capas independientes de control de acceso:

**Por CN mTLS del broker:** `callers` en `signer.json` mapea el CN del certificado cliente del broker a los grupos de hosts a los que tiene acceso. `GET /v1/hosts` filtra la respuesta; `POST /v1/sign` rechaza (403) hosts fuera del grupo antes de llegar a `Resolve()`.

**Por usuario final (OIDC):** si el token porta un `groups_claim`, los grupos se propagan al signer como `EndUserGroups`. El signer require `host.Groups ∩ EndUserGroups ≠ ∅`. Si `EndUserGroups` es nil (petición stdio o mTLS sin identidad de usuario), el filtro no se aplica.

Un CN ausente de `callers` no tiene restricción de grupo (backward compatible).

### 4.10 Grabación de sesiones (v1.10.0)

Las sesiones `shell` y `pty` pueden grabarse en ficheros **ASCIIcast v2** para replay forense, compliance y auditoría. Se activa con un campo de configuración:

```json
"session_recording_dir": "/var/log/ssh-broker/recordings"
```

Un fichero por sesión: `<session_id>.cast`. El nombre correlaciona directamente con el campo `session_id` del audit log del broker, que actúa como índice de búsqueda.

Tres streams capturados con timestamps de milisegundo:
- `"i"` — stdin: el comando que el agente escribe, antes de enviarlo al canal SSH.
- `"o"` — stdout: salida de cada línea, o el stream PTY mezclado.
- `"e"` — stderr: bytes según llegan (solo modo no-PTY).

La cabecera del fichero incluye el campo privado `ssh_broker` con `session_id`, `caller`, `host`, `serial` y `started_at`. El fichero es autodesriptivo sin necesidad del audit log. Reproducible con `asciinema play`.

### 4.11 Log de auditoría criptográficamente encadenado

Tres fuentes de auditoría correladas por `serial`:

1. **Log del signer** (`signer_audit.log`): cada emisión o denegación de certificado. Campos: caller, host:port real (FQDN), user, principal, elevation, PTY, serial.
2. **Log del broker** (`audit.log`): cada ejecución, denegación o evento de sesión. Campos: caller, host, command, exit_code, session_id, elevation, PTY, policy_rule, dry_run, approval_id.
3. **Log de sshd** (`/var/log/auth.log`): `Accepted certificate ID "agent=... host=... elev=... pty=1"` con serial.

Cada entrada se firma con Ed25519 y encadena por SHA-256 del JSON de la entrada anterior. Cualquier modificación o reordenación rompe todas las hashes posteriores. El broker-ctl verifica la cadena con `audit verify --log <f> --key <seed>`. Rotación automática a los 100 MiB con sufijo de timestamp.

### 4.12 Recarga en caliente del signer

El signer puede recargar `signer.json` sin reiniciar: política de hosts, `max_ttl_seconds` y clave CA se reemplazan atómicamente. Si la nueva configuración es inválida, se conserva el estado anterior.

Dos mecanismos: `POST /v1/reload` (mTLS, restringido a CNs en `reload_callers`) y `SIGHUP` (local, bypass de la allowlist). `listen`, TLS y `audit_log` requieren reinicio.

### 4.13 CLI broker-ctl

Herramienta de gestión completa:
- `host add/list/remove` — gestión de hosts con `ssh-keyscan` automático.
- `reload` — SIGHUP si el signer corre en local, POST HTTP como fallback.
- `approval list/allow/deny` — gestión de solicitudes de aprobación (mTLS al control plane).
- `audit tail/show/verify` — visualización y verificación del log de auditoría.

Preserva campos `_comment` del JSON al editar (escritura atómica vía rename).

---

## 5. Hardening de seguridad

Doce controles implementados en v1.4.1 como resultado de una revisión de seguridad:

| ID | Severidad | Control |
|---|---|---|
| C1 | Crítica | `SessionExec`/`CloseSession` verifican propiedad antes de operar |
| A1 | Alta | `ReadTimeout`/`WriteTimeout`/`IdleTimeout` en `http.Server` |
| A2 | Alta | `MaxBytesReader(64 KiB)` en `/v1/sign`; `LimitReader(1 MiB)` en remote.go |
| A3 | Alta | Timeout de ejecución SSH 10 min; output capped 10 MiB; SIGTERM en timeout |
| A4 | Alta | `restoreChain()` restaura seq+prevHash al reiniciar: cadena ininterrumpida |
| M1 | Media | Errores de `auditLog.Append` registrados vía `log.Printf` |
| M2 | Media | `maxSessionsGlobal=200`, `maxSessionsPerCaller=20` |
| M3 | Media | Validación de claim `iat` para limitar replay de tokens filtrados |
| M5 | Media | `SessionExec` rechaza comandos con `\n`/`\r` (anti-inyección newline) |
| L1 | Baja | `LoadCAFromPEM` emite `[WARN]` en runtime |
| L2 | Baja | `maybeRotate()` rota el audit log a los 100 MiB |
| L4 | Baja | `validateInput()` en tools MCP: límite 64 KiB, rechaza bytes nulos |

---

## 6. Métricas del proyecto

### 6.1 Código

| Métrica | Valor |
|---|---|
| Periodo de desarrollo | 7 días (3–9 junio 2026) |
| Versiones etiquetadas | v1.0.0 → v1.10.0 (17 tags) |
| Commits | 55 |
| Líneas de código Go (producción) | 6.762 |
| Líneas de código Go (tests) | 3.941 |
| Total líneas Go | 10.703 |
| Paquetes Go | 16 (6 binarios + 10 internos) |

### 6.2 Cobertura de tests

156 casos en 12 paquetes. Todos pasan con `go test -race ./...` sin data races.

| Paquete | Casos | Cobertura |
|---|---|---|
| `internal/signer` | 39 | Completa: policy, RBAC, sudo, PTY, dry-run, approval gate, shell_parse |
| `internal/control` | 39 | Completa: approval registry, behavior tracker, Teams notifier |
| `internal/broker` | 25 | Completa: sessionManager, C1 ownership, M5 newlines, dry-run |
| `cmd/broker-ctl` | 17 | Completa: verifyLog (cadena, firmas, gaps), lastNLines, parseAuditTime |
| `internal/audit` | 11 | Completa: cadena hash, firmas Ed25519, restoreChain, maybeRotate |
| `internal/recording` | 8 | Completa: cabecera, tipos de evento, deltas, concurrencia, close |
| `cmd/control-plane` | 8 | Completa: forwarding, approval flow, behavior, ownership |
| `internal/oauth` | 5 | Completa: valid/expired/wrong-aud/bad-sig/missing-claim |
| `internal/ca` | 4 | Completa: sign, bastion, TTL, cert verify |
| `cmd/signer` | 4 | resolveCaller (4 sub-tests) |
| `cmd/mcp-broker-http` | 3 | OAuth auth, 401, RFC 9728 |

63 tests unitarios en `internal/` ejecutan `t.Parallel()` para máxima detección de data races.

### 6.3 Historial de versiones

| Versión | Fecha | Hito principal |
|---|---|---|
| v1.0.0 | 2026-06-03 | Broker MCP stdio, signer externo, sesiones shell/pty, audit encadenado |
| v1.1.0 | 2026-06-04 | broker-ctl (host add/list/remove, reload, audit) |
| v1.2.0 | 2026-06-04 | ssh_list_servers con capacidades (allow_sudo, allow_pty, jump) |
| v1.4.0 | 2026-06-04 | Frontend HTTP+OAuth2/OIDC (cmd/mcp-broker-http), RBAC por usuario |
| v1.4.1 | 2026-06-05 | 12 controles de hardening de seguridad |
| v1.5.0 | 2026-06-06 | AI-action firewall: command policy + dry-run (Fase A) |
| v1.6.0 | 2026-06-06 | Control plane + aprobación humana (Fase B) |
| v1.7.0 | 2026-06-08 | Guardrails de comportamiento + rate limiting (Fase C) |
| v1.8.0 | 2026-06-08 | Teams notifier (Adaptive Card v1.4 + MessageCard) |
| v1.9.0 | 2026-06-08 | context.Context en toda la pila de llamadas |
| v1.9.1 | 2026-06-08 | Refactor funciones largas, CODING_STYLE.md |
| v1.9.2 | 2026-06-09 | Shell AST parsing en CommandPolicy (mvdan.cc/sh/v3) |
| v1.9.3 | 2026-06-09 | Normalización total al inglés: comentarios Go, CHANGELOG, strings |
| v1.10.0 | 2026-06-09 | Grabación de sesiones en ASCIIcast v2 (stdin+stdout+stderr) |

---

## 7. Decisiones de diseño relevantes

### 7.1 Separación signer/broker (invariante central)

La clave privada de la CA nunca sale del `cmd/signer`. El broker solo recibe el certificado firmado. Esto garantiza que un broker comprometido no puede generar certificados válidos ni eludir la política. El signer es el único componente que necesita protección de nivel HSM/KMS, y el seam ya está preparado (`ca.LoadCAFromPEM` devuelve `ssh.Signer`, sustituible por `ssh.NewSignerFromSigner(kmsClient)`).

### 7.2 Force-command solo en one-shot

El certificado de un one-shot lleva `force-command` baked por la clave CA: el sshd impone el comando exacto independientemente de lo que diga el broker. En sesiones el certificado autentica la conexión, no cada comando (el comando llega después de la emisión). La seguridad en sesiones recae en TTL + source-address + policy sudoers del host.

### 7.3 Aprobación inevadible vía trusted_forwarders

Un broker no puede auto-aprobarse: el signer solo honra `approved=true` cuando viene del CN del control plane, que está en `trusted_forwarders`. Un broker que llame al signer directamente no puede suplantar esta señal. El control plane tampoco custodia la clave CA, siguiendo el patrón PEP/PDP de zero-trust.

### 7.4 Shell AST vs regex puras

El parsing de gramática shell antes de evaluar las reglas regex resuelve estructuralmente el bypass de compound commands (`ps aux && kill -9 1000` contra `^ps`). La alternativa —reglas deny sobre metacaracteres— es frágil porque cualquier operador olvidado es un bypass. El AST walk es determinista y la biblioteca `mvdan.cc/sh/v3` tiene tiempo lineal garantizado (RE2).

### 7.5 ASCIIcast v2 para grabación

El formato estándar de facto para grabaciones de terminal: compatible con `asciinema play`, con herramientas SIEM, y parseable con `jq` para análisis de stdin. El fichero es autodesriptivo (la cabecera incluye `session_id`, `caller`, `host`, `serial`) y correlaciona con el audit log por nombre de fichero. No requiere infraestructura adicional: es un fichero append-only en un directorio local.

---

## 8. Deuda técnica pendiente (producción)

### Alta prioridad
- **Clave CA en HSM/KMS**: el seam está preparado. Sustituir `ca.LoadCAFromPEM` por `ssh.NewSignerFromSigner(kmsClient)`.
- **Multi-instancia de sessions**: el `sessionManager` es in-process. Con múltiples réplicas del broker se necesita externalizar a Redis con TTL.

### Media prioridad
- **KRL (Key Revocation List)**: endpoint `/v1/revoke` para invalidar certificados por serial antes de su TTL.
- **Logs a almacenamiento WORM**: enviar el log de auditoría (ya firmado y encadenado) a S3/GCS/SIEM en tiempo real.
- **Teams approval bridge**: bot de Bot Framework + `cmd/approval-bridge` para aprobar desde la card de Teams con identidad real de Entra ID.
- **Una CA por grupo de hosts**: hoy hay una sola clave CA global. Vincular cada grupo a su propia CA limita el radio de explosión de un compromiso.

### Baja prioridad
- **Hosts dinámicos**: modo `allow_dynamic_hosts` para que el agente suministre addr/user/host_key sin declaración previa en el signer.
- **Dashboard de auditoría**: visualización de logs correlados por serial.
- **Tests de sshd embebido**: el protocolo de marcadores de `ShellSession` requiere un servidor SSH real o `gliderlabs/ssh` para tests de integración completos.

---

## 9. Documentación generada

Junto al código se generaron los siguientes artefactos de documentación:

| Fichero | Descripción |
|---|---|
| `README.md` | Documentación técnica completa en inglés |
| `USAGE.md` | Guía de uso de las 5 tools MCP, sudo, PTY, audit y grabación |
| `API.md` | Referencia de endpoints HTTP de todos los servicios |
| `CODING_STYLE.md` | Reglas de estilo Go con criterio mecánico de verificación |
| `HANDOFF.md` | Documento de traspaso para retomar el desarrollo |
| `CHANGELOG.md` | Historial de versiones en inglés |
| `medium.txt` | Borrador de post para Medium (v1.10.0) |
| `make_presentation.py` | Script Python que genera una presentación corporativa de 31 diapositivas en estilo editorial Zara (python-pptx) |
| `config.example.json` | Configuración de referencia del broker |
| `signer.example.json` | Configuración de referencia del signer |
| `control-plane.example.json` | Configuración de referencia del control plane |

---

## 10. Conclusiones

SSH Broker demuestra que es posible construir en una semana una infraestructura de acceso SSH segura para agentes de IA que resuelve el problema fundamental de las credenciales estáticas, sin depender de productos de infraestructura pesados.

El sistema cubre en un solo binario Go (o un conjunto pequeño de binarios) lo que otros productos —Teleport, Vault SSH, StrongDM— ofrecen solo con clusters de control-plane o dependencias de servidor. La diferencia es de escala y complejidad operativa, no de modelo de seguridad.

Las decisiones de arquitectura más importantes —separación signer/broker, force-command en el certificado, trusted_forwarders para aprobación, AST parsing de comandos shell— son todas invariantes de seguridad que no se pueden eludir desde el lado del agente, que es precisamente el atacante que se quiere defender.

El proyecto queda en estado funcional y desplegable para uso real, con la ruta hacia producción claramente marcada: HSM/KMS para la clave CA, alta disponibilidad del broker con sesiones externalizadas, y la aprobación bidireccional desde Teams.
