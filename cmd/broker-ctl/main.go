// broker-ctl gestiona la configuración del signer (signer.json), fuerza recargas
// y permite revisar los logs de auditoría.
//
// Uso:
//
//	broker-ctl host add    [flags]          # Añade o actualiza un host
//	broker-ctl host list   [--config f]     # Lista hosts configurados
//	broker-ctl host remove [--config f] <nombre>
//	broker-ctl reload      [--config f] [flags]           # Recarga signer
//	broker-ctl audit tail   --log <f> [-n N]              # Sigue el log en tiempo real
//	broker-ctl audit show   --log <f> [filtros] [--json]  # Busca/filtra entradas
//	broker-ctl audit verify --log <f> [--key seed]        # Verifica integridad de cadena
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

const defaultConfig = "./signer.json"

func main() {
	if len(os.Args) < 2 {
		usageTop()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "host":
		cmdHost(os.Args[2:])
	case "reload":
		cmdReload(os.Args[2:])
	case "approval":
		cmdApproval(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "help", "--help", "-h":
		usageTop()
	default:
		fmt.Fprintf(os.Stderr, "subcomando desconocido: %q\n", os.Args[1])
		usageTop()
		os.Exit(1)
	}
}

func usageTop() {
	fmt.Fprintln(os.Stderr, `broker-ctl — gestión de configuración del SSH broker

Uso:
  broker-ctl host add    [--config f] [flags]      Añade o actualiza un host
  broker-ctl host list   [--config f]              Lista hosts configurados
  broker-ctl host remove [--config f] <nombre>     Elimina un host
  broker-ctl reload      [--config f] [flags]      Recarga el signer
  broker-ctl approval list  [flags]                Lista solicitudes de aprobación (control plane)
  broker-ctl approval allow <id> [flags]           Aprueba una solicitud
  broker-ctl approval deny  <id> [flags]           Deniega una solicitud
  broker-ctl audit tail   --log <f> [-n N]         Sigue el log de auditoría en tiempo real
  broker-ctl audit show   --log <f> [filtros]      Busca y filtra entradas del log
  broker-ctl audit verify --log <f> [--key seed]   Verifica la integridad de la cadena

Opciones globales:
  --config   Ruta a signer.json (default: ./signer.json)`)
}

// ── host ──────────────────────────────────────────────────────────────────────

func cmdHost(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Uso: broker-ctl host {add|list|remove} [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "add":
		cmdHostAdd(args[1:])
	case "list":
		cmdHostList(args[1:])
	case "remove", "rm", "del":
		cmdHostRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "subcomando host desconocido: %q\n", args[0])
		os.Exit(1)
	}
}

func cmdHostAdd(args []string) {
	fs := flag.NewFlagSet("host add", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	name := fs.String("name", "", "nombre lógico del host (obligatorio)")
	addr := fs.String("addr", "", "host:port del servidor SSH (obligatorio)")
	user := fs.String("user", "", "cuenta SSH remota (obligatorio)")
	hostKey := fs.String("host-key", "", "host key en formato authorized_keys (o '-' para stdin)")
	scan := fs.Bool("scan", false, "obtener host key automáticamente con ssh-keyscan")
	principal := fs.String("principal", "", "principal SSH en el cert (default: host:<name>)")
	ttl := fs.Int("ttl", 120, "max_ttl_seconds")
	jump := fs.String("jump", "", "nombre lógico del bastión previo")
	sourceAddr := fs.String("source-address", "", "IP/CIDR de egreso del bastión")
	allowSudo := fs.Bool("sudo", false, "allow_sudo=true")
	sudoUsers := fs.String("sudo-users", "", "allowed_sudo_users separados por comas")
	allowPTY := fs.Bool("pty", false, "allow_pty=true")
	groups := fs.String("groups", "", "grupos RBAC separados por comas")
	callers := fs.String("callers", "", "CNs permitidos separados por comas")
	bastion := fs.Bool("bastion", false, "allow_as_bastion=true")
	force := fs.Bool("force", false, "sobrescribir si ya existe")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Uso: broker-ctl host add --name <n> --addr <h:p> --user <u> {--host-key <k>|--scan} [flags]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))

	if *name == "" || *addr == "" || *user == "" {
		fs.Usage()
		os.Exit(1)
	}
	if !*scan && *hostKey == "" {
		fmt.Fprintln(os.Stderr, "error: se requiere --host-key o --scan")
		fs.Usage()
		os.Exit(1)
	}
	if *scan && *hostKey != "" {
		fmt.Fprintln(os.Stderr, "error: --host-key y --scan son excluyentes")
		os.Exit(1)
	}

	var hk string
	if *scan {
		host, _, _ := strings.Cut(*addr, ":")
		var err error
		hk, err = sshKeyscan(host)
		if err != nil {
			fatalf("ssh-keyscan: %v", err)
		}
	} else if *hostKey == "-" {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(os.Stdin); err != nil {
			fatalf("leer stdin: %v", err)
		}
		hk = strings.TrimSpace(buf.String())
	} else {
		hk = *hostKey
	}

	if *principal == "" {
		*principal = "host:" + *name
	}

	hp := hostEntry{
		Addr:          *addr,
		User:          *user,
		HostKey:       hk,
		Principal:     *principal,
		MaxTTLSeconds: *ttl,
	}
	if *jump != "" {
		hp.Jump = *jump
	}
	if *sourceAddr != "" {
		hp.SourceAddress = *sourceAddr
	}
	if *bastion {
		hp.AllowAsBastion = true
	}
	if *allowSudo {
		hp.AllowSudo = true
	}
	if *sudoUsers != "" {
		hp.AllowedSudoUsers = splitComma(*sudoUsers)
	}
	if *allowPTY {
		hp.AllowPTY = true
	}
	if *groups != "" {
		hp.Groups = splitComma(*groups)
	}
	if *callers != "" {
		hp.AllowedCallers = splitComma(*callers)
	}

	raw, err := loadRaw(*config)
	if err != nil {
		fatalf("leer config: %v", err)
	}

	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsear hosts: %v", err)
	}
	if _, exists := hosts[*name]; exists && !*force {
		fatalf("host %q ya existe (usa --force para sobrescribir)", *name)
	}

	hosts[*name] = hp
	if err := writeHosts(*config, raw, hosts); err != nil {
		fatalf("escribir config: %v", err)
	}

	action := "añadido"
	if _, exists := hosts[*name]; exists && *force {
		action = "actualizado"
	}
	fmt.Printf("host %q %s (addr=%s, user=%s, principal=%s)\n", *name, action, *addr, *user, *principal)
}

func cmdHostList(args []string) {
	fs := flag.NewFlagSet("host list", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	must(fs.Parse(args))

	raw, err := loadRaw(*config)
	if err != nil {
		fatalf("leer config: %v", err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsear hosts: %v", err)
	}

	if len(hosts) == 0 {
		fmt.Println("(no hay hosts configurados)")
		return
	}

	names := make([]string, 0, len(hosts))
	for n := range hosts {
		names = append(names, n)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDR\tUSER\tPRINCIPAL\tTTL\tSUDO\tPTY\tBASTION\tGROUPS")
	for _, n := range names {
		h := hosts[n]
		sudo := boolStr(h.AllowSudo)
		pty := boolStr(h.AllowPTY)
		bas := boolStr(h.AllowAsBastion)
		grps := strings.Join(h.Groups, ",")
		if grps == "" {
			grps = "—"
		}
		ttl := strconv.Itoa(h.MaxTTLSeconds) + "s"
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			n, h.Addr, h.User, h.Principal, ttl, sudo, pty, bas, grps)
	}
	w.Flush()
}

func cmdHostRemove(args []string) {
	fs := flag.NewFlagSet("host remove", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Uso: broker-ctl host remove [--config f] <nombre>")
	}
	must(fs.Parse(args))

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	name := fs.Arg(0)

	raw, err := loadRaw(*config)
	if err != nil {
		fatalf("leer config: %v", err)
	}
	hosts, err := extractHosts(raw)
	if err != nil {
		fatalf("parsear hosts: %v", err)
	}
	if _, exists := hosts[name]; !exists {
		fatalf("host %q no encontrado", name)
	}

	delete(hosts, name)
	if err := writeHosts(*config, raw, hosts); err != nil {
		fatalf("escribir config: %v", err)
	}
	fmt.Printf("host %q eliminado\n", name)
}

// ── reload ────────────────────────────────────────────────────────────────────

func cmdReload(args []string) {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	config := fs.String("config", defaultConfig, "ruta a signer.json")
	pidFile := fs.String("pid-file", "./signer.pid", "ruta al PID file del signer")
	cert := fs.String("cert", "./pki/broker.crt", "cert cliente mTLS para /v1/reload")
	key := fs.String("key", "./pki/broker.key", "clave cliente mTLS")
	ca := fs.String("ca", "./pki/mtls_ca.crt", "CA mTLS")
	must(fs.Parse(args))

	// Intentar SIGHUP local primero.
	if pid, err := readPID(*pidFile); err == nil {
		if isAlive(pid) {
			if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
				fatalf("SIGHUP a PID %d: %v", pid, err)
			}
			fmt.Printf("SIGHUP enviado al signer (PID %d)\n", pid)
			return
		}
	}

	// Fallback: POST /v1/reload vía mTLS.
	signerURL, err := readSignerURL(*config)
	if err != nil {
		fatalf("leer URL del signer desde config: %v", err)
	}
	url := "https://" + signerURL + "/v1/reload"

	tlsCfg, err := buildTLSConfig(*cert, *key, *ca)
	if err != nil {
		fatalf("TLS: %v", err)
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	resp, err := client.Post(url, "application/json", nil)
	if err != nil {
		fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
		Hosts  int    `json:"hosts"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fatalf("parsear respuesta: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatalf("signer rechazó recarga (HTTP %d): %s", resp.StatusCode, result.Error)
	}
	fmt.Printf("signer recargado vía HTTP (hosts: %d)\n", result.Hosts)
}

// ── approval (control plane) ────────────────────────────────────────────────────

func cmdApproval(args []string) {
	if len(args) < 1 {
		fatalf("uso: broker-ctl approval <list|allow|deny> [id] [flags]")
	}
	switch args[0] {
	case "list":
		cmdApprovalList(args[1:])
	case "allow", "approve":
		cmdApprovalDecide(args[1:], true)
	case "deny", "reject":
		cmdApprovalDecide(args[1:], false)
	default:
		fatalf("subcomando de approval desconocido: %q (list|allow|deny)", args[0])
	}
}

// approvalFlags registra los flags mTLS comunes hacia el control plane.
func approvalFlags(fs *flag.FlagSet) (url, cert, key, ca *string) {
	url = fs.String("url", "127.0.0.1:7443", "host:puerto del control plane")
	cert = fs.String("cert", "./pki/broker-admin.crt", "cert cliente mTLS (aprobador)")
	key = fs.String("key", "./pki/broker-admin.key", "clave cliente mTLS")
	ca = fs.String("ca", "./pki/mtls_ca.crt", "CA mTLS")
	return
}

func approvalClient(cert, key, ca string) *http.Client {
	tlsCfg, err := buildTLSConfig(cert, key, ca)
	if err != nil {
		fatalf("TLS: %v", err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

func cmdApprovalList(args []string) {
	fs := flag.NewFlagSet("approval list", flag.ExitOnError)
	url, cert, key, ca := approvalFlags(fs)
	asJSON := fs.Bool("json", false, "salida JSON cruda")
	must(fs.Parse(args))

	client := approvalClient(*cert, *key, *ca)
	resp, err := client.Get("https://" + *url + "/v1/approvals")
	if err != nil {
		fatalf("GET /v1/approvals: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("control plane devolvió %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(body))
		return
	}
	var items []struct {
		ID        string `json:"id"`
		Caller    string `json:"caller"`
		EndUser   string `json:"end_user"`
		Host      string `json:"host"`
		Command   string `json:"command"`
		Rule      string `json:"rule"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		fatalf("parsear respuesta: %v", err)
	}
	if len(items) == 0 {
		fmt.Println("(sin solicitudes)")
		return
	}
	for _, it := range items {
		user := it.EndUser
		if user == "" {
			user = "-"
		}
		fmt.Printf("%s  [%s]  caller=%s user=%s host=%s\n    cmd=%q rule=%s\n",
			it.ID, it.Status, it.Caller, user, it.Host, it.Command, it.Rule)
	}
}

func cmdApprovalDecide(args []string, approve bool) {
	fs := flag.NewFlagSet("approval decide", flag.ExitOnError)
	url, cert, key, ca := approvalFlags(fs)
	must(fs.Parse(args))
	if fs.NArg() < 1 {
		fatalf("falta el id de la solicitud")
	}
	id := fs.Arg(0)

	client := approvalClient(*cert, *key, *ca)
	body, _ := json.Marshal(map[string]bool{"approve": approve})
	resp, err := client.Post("https://"+*url+"/v1/approvals/"+id, "application/json", bytes.NewReader(body))
	if err != nil {
		fatalf("POST /v1/approvals/%s: %v", id, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("control plane rechazó la decisión (HTTP %d): %s", resp.StatusCode, bytes.TrimSpace(rb))
	}
	verb := "denegada"
	if approve {
		verb = "aprobada"
	}
	fmt.Printf("solicitud %s %s\n", id, verb)
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

// hostEntry es la representación JSON de un host en signer.json.
type hostEntry struct {
	Addr             string   `json:"addr"`
	User             string   `json:"user"`
	HostKey          string   `json:"host_key"`
	Jump             string   `json:"jump,omitempty"`
	Principal        string   `json:"principal"`
	SourceAddress    string   `json:"source_address,omitempty"`
	MaxTTLSeconds    int      `json:"max_ttl_seconds,omitempty"`
	AllowAsBastion   bool     `json:"allow_as_bastion,omitempty"`
	AllowedCallers   []string `json:"allowed_callers,omitempty"`
	AllowSudo        bool     `json:"allow_sudo,omitempty"`
	AllowedSudoUsers []string `json:"allowed_sudo_users,omitempty"`
	AllowPTY         bool     `json:"allow_pty,omitempty"`
	Groups           []string `json:"groups,omitempty"`
}

// loadRaw lee signer.json como mapa de RawMessage para preservar campos desconocidos.
func loadRaw(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("JSON inválido: %w", err)
	}
	return raw, nil
}

// extractHosts extrae y parsea la clave "hosts" del raw map.
func extractHosts(raw map[string]json.RawMessage) (map[string]hostEntry, error) {
	hostsRaw, ok := raw["hosts"]
	if !ok {
		return map[string]hostEntry{}, nil
	}
	var hosts map[string]hostEntry
	if err := json.Unmarshal(hostsRaw, &hosts); err != nil {
		return nil, err
	}
	if hosts == nil {
		hosts = map[string]hostEntry{}
	}
	return hosts, nil
}

// writeHosts serializa hosts de vuelta al raw map y escribe el archivo.
func writeHosts(path string, raw map[string]json.RawMessage, hosts map[string]hostEntry) error {
	hostsJSON, err := json.MarshalIndent(hosts, "  ", "  ")
	if err != nil {
		return err
	}
	raw["hosts"] = hostsJSON

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	// Escritura atómica: escribir a temp y renombrar.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readSignerURL extrae el campo "listen" de signer.json para construir la URL HTTP.
func readSignerURL(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg struct {
		Listen string `json:"listen"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	if cfg.Listen == "" {
		return "", errors.New("campo 'listen' vacío en signer.json")
	}
	// Si listen es ":9443" (sin host), usar 127.0.0.1.
	if strings.HasPrefix(cfg.Listen, ":") {
		return "127.0.0.1" + cfg.Listen, nil
	}
	return cfg.Listen, nil
}

// ── TLS / PID helpers ─────────────────────────────────────────────────────────

func buildTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("cargar cert cliente: %w", err)
	}
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("leer CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("CA PEM inválido")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

func readPID(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("PID inválido en %s: %w", pidFile, err)
	}
	return pid, nil
}

func isAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// sshKeyscan ejecuta ssh-keyscan y extrae la primera línea ed25519.
func sshKeyscan(host string) (string, error) {
	out, err := exec.Command("ssh-keyscan", "-t", "ed25519", host).Output()
	if err != nil {
		return "", fmt.Errorf("ssh-keyscan falló: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Formato: "hostname ssh-ed25519 AAAA..."
		// Eliminar el prefijo del hostname.
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			return strings.Join(parts[1:], " "), nil
		}
	}
	return "", fmt.Errorf("ssh-keyscan no devolvió una clave ed25519 para %s", host)
}

// ── misc ──────────────────────────────────────────────────────────────────────

func splitComma(s string) []string {
	var result []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			result = append(result, p)
		}
	}
	return result
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

// ── audit ─────────────────────────────────────────────────────────────────────

// auditEntry mirrors internal/audit.Entry without importing that package.
// Field order must be identical for Ed25519 signature verification: json.Marshal
// produces fields in struct-definition order, so any divergence breaks --key.
type auditEntry struct {
	Time      time.Time `json:"time"`
	Caller    string    `json:"caller"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	Principal string    `json:"principal"`
	Command   string    `json:"command"`
	TTL       string    `json:"ttl"`
	Serial    uint64    `json:"serial"`
	SessionID string    `json:"session_id,omitempty"`
	Outcome   string    `json:"outcome"`
	ExitCode  int       `json:"exit_code"`
	Err       string    `json:"err,omitempty"`
	Elevation string    `json:"elevation,omitempty"`
	PTY       bool      `json:"pty,omitempty"`
	Seq       uint64    `json:"seq"`
	PrevHash  string    `json:"prev_hash"`
	Sig       string    `json:"sig"`
}

func cmdAudit(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit {tail|show|verify} [flags]")
		os.Exit(1)
	}
	switch args[0] {
	case "tail":
		cmdAuditTail(args[1:])
	case "show":
		cmdAuditShow(args[1:])
	case "verify":
		cmdAuditVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand: %q\n", args[0])
		os.Exit(1)
	}
}

func cmdAuditTail(args []string) {
	fs := flag.NewFlagSet("audit tail", flag.ExitOnError)
	logPath := fs.String("log", "", "path to audit log file (required)")
	n := fs.Int("n", 20, "number of recent entries to show before following")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit tail --log <path> [-n N]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *logPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	printAuditHeader(w)

	lines, offset, err := lastNLines(*logPath, *n)
	if err != nil && !os.IsNotExist(err) {
		fatalf("open log: %v", err)
	}
	for _, line := range lines {
		printAuditLine(w, line)
	}
	w.Flush()

	// Stream new entries as they are written.
	followFile(*logPath, offset, func(line []byte) {
		printAuditLine(w, line)
		w.Flush()
	})
}

func cmdAuditShow(args []string) {
	fs := flag.NewFlagSet("audit show", flag.ExitOnError)
	logPath := fs.String("log", "", "path to audit log file (required)")
	host := fs.String("host", "", "filter by host (substring match)")
	caller := fs.String("caller", "", "filter by caller (substring match)")
	outcome := fs.String("outcome", "", "filter by exact outcome (e.g. executed, denied, issued)")
	serial := fs.Uint64("serial", 0, "filter by exact serial number (0 = no filter)")
	since := fs.String("since", "", "show entries after this time (RFC3339 or YYYY-MM-DD)")
	limit := fs.Int("limit", 0, "max entries to return (0 = no limit)")
	asJSON := fs.Bool("json", false, "output as raw JSON lines (compatible with jq)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit show --log <path> [filters] [--json]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *logPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	var sinceTime time.Time
	if *since != "" {
		var err error
		sinceTime, err = parseAuditTime(*since)
		if err != nil {
			fatalf("invalid --since value %q: %v", *since, err)
		}
	}

	f, err := os.Open(*logPath)
	if err != nil {
		fatalf("open log: %v", err)
	}
	defer f.Close()

	var tw *tabwriter.Writer
	if !*asJSON {
		tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		printAuditHeader(tw)
	}

	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e auditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip malformed lines silently
		}

		// Apply filters (all ANDed).
		if *host != "" && !strings.Contains(e.Host, *host) {
			continue
		}
		if *caller != "" && !strings.Contains(e.Caller, *caller) {
			continue
		}
		if *outcome != "" && e.Outcome != *outcome {
			continue
		}
		if *serial != 0 && e.Serial != *serial {
			continue
		}
		if !sinceTime.IsZero() && e.Time.Before(sinceTime) {
			continue
		}

		if *asJSON {
			os.Stdout.Write(line)
			os.Stdout.Write([]byte{'\n'})
		} else {
			printAuditRow(tw, e)
		}
		count++
		if *limit > 0 && count >= *limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		fatalf("read error: %v", err)
	}
	if !*asJSON {
		tw.Flush()
		if count == 0 {
			fmt.Fprintln(os.Stderr, "(no matching entries)")
		}
	}
}

func cmdAuditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	logPath := fs.String("log", "", "path to audit log file (required)")
	keyPath := fs.String("key", "", "path to audit seed file for Ed25519 signature verification (optional)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: broker-ctl audit verify --log <path> [--key seed-path]")
		fs.PrintDefaults()
	}
	must(fs.Parse(args))
	if *logPath == "" {
		fs.Usage()
		os.Exit(1)
	}

	// Derive public key from seed if provided.
	var pubKey ed25519.PublicKey
	if *keyPath != "" {
		seed, err := os.ReadFile(*keyPath)
		if err != nil {
			fatalf("read key: %v", err)
		}
		if len(seed) < ed25519.SeedSize {
			fatalf("seed file too short (need %d bytes, got %d)", ed25519.SeedSize, len(seed))
		}
		privKey := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
		pubKey = privKey.Public().(ed25519.PublicKey)
	}

	f, err := os.Open(*logPath)
	if err != nil {
		fatalf("open log: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)

	var prevHash string
	var prevSeq uint64
	total, errs := 0, 0
	first := true

	for sc.Scan() {
		rawLine := sc.Bytes()
		if len(rawLine) == 0 {
			continue
		}
		// Copy before next Scan() invalidates the buffer.
		line := make([]byte, len(rawLine))
		copy(line, rawLine)

		var e auditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: malformed JSON (seq %d): %v\n", e.Seq, err)
			errs++
			continue
		}
		total++

		// 1. Sequence monotonicity.
		if !first && e.Seq != prevSeq+1 {
			fmt.Fprintf(os.Stderr, "ERROR: seq %d — expected %d (gap or reorder)\n", e.Seq, prevSeq+1)
			errs++
		}

		// 2. Hash chain: prev_hash of entry N must equal SHA-256 of raw line N-1.
		if !first && e.PrevHash != prevHash {
			fmt.Fprintf(os.Stderr, "ERROR: seq %d — prev_hash mismatch\n  expected: %s\n  got:      %s\n",
				e.Seq, prevHash, e.PrevHash)
			errs++
		}

		// 3. Ed25519 signature (optional).
		if pubKey != nil {
			sigB64 := e.Sig
			sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: seq %d — invalid sig encoding: %v\n", e.Seq, err)
				errs++
			} else {
				// Canonical payload is the entry marshaled with Sig="".
				e.Sig = ""
				payload, merr := json.Marshal(e)
				if merr != nil {
					fmt.Fprintf(os.Stderr, "ERROR: seq %d — marshal for sig check: %v\n", e.Seq, merr)
					errs++
				} else if !ed25519.Verify(pubKey, payload, sigBytes) {
					fmt.Fprintf(os.Stderr, "ERROR: seq %d — signature invalid\n", e.Seq)
					errs++
				}
				e.Sig = sigB64
			}
		}

		sum := sha256.Sum256(line)
		prevHash = hex.EncodeToString(sum[:])
		prevSeq = e.Seq
		first = false
	}
	if err := sc.Err(); err != nil {
		fatalf("read error: %v", err)
	}

	if errs == 0 {
		if pubKey != nil {
			fmt.Printf("OK: %d entries, chain intact, all signatures valid\n", total)
		} else {
			fmt.Printf("OK: %d entries, chain intact (pass --key to also verify signatures)\n", total)
		}
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: %d entries checked, %d error(s) found\n", total, errs)
		os.Exit(1)
	}
}

// printAuditHeader writes the column header for the audit table.
func printAuditHeader(w *tabwriter.Writer) {
	fmt.Fprintln(w, "TIME\tSEQ\tCALLER\tHOST\tOUTCOME\tSERIAL\tDETAIL")
}

// printAuditLine parses a raw JSON line and appends one table row.
func printAuditLine(w *tabwriter.Writer, line []byte) {
	var e auditEntry
	if err := json.Unmarshal(line, &e); err != nil {
		return
	}
	printAuditRow(w, e)
}

// printAuditRow formats a single audit entry as a tab-delimited row.
func printAuditRow(w *tabwriter.Writer, e auditEntry) {
	t := e.Time.UTC().Format("2006-01-02T15:04:05Z")
	fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%d\t%s\n",
		t, e.Seq, e.Caller, e.Host, e.Outcome, e.Serial, auditDetail(e))
}

// auditDetail builds the DETAIL column: command + [sudo:X] [pty] [err: ...].
func auditDetail(e auditEntry) string {
	var b strings.Builder
	b.WriteString(e.Command)
	if e.Elevation != "" {
		fmt.Fprintf(&b, " [%s]", e.Elevation)
	}
	if e.PTY {
		b.WriteString(" [pty]")
	}
	if e.Err != "" {
		fmt.Fprintf(&b, " [err: %s]", e.Err)
	}
	return b.String()
}

// lastNLines reads the last n non-empty lines of path and returns them together
// with the file's current byte offset (used as the start position for followFile).
func lastNLines(path string, n int) ([][]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	var ring [][]byte
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		ring = append(ring, line)
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return ring, 0, nil
	}
	return ring, size, nil
}

// followFile polls path every 500 ms and calls fn for each new complete line.
// If the file shrinks (log rotation), it restarts from the beginning of the
// new file.
func followFile(path string, offset int64, fn func([]byte)) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if fi.Size() < offset {
			offset = 0 // rotation: restart from top
		}
		if fi.Size() == offset {
			continue // no new data
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 256*1024), 256*1024)
		for sc.Scan() {
			b := sc.Bytes()
			offset += int64(len(b)) + 1 // +1 for the stripped newline
			if len(b) == 0 {
				continue
			}
			line := make([]byte, len(b))
			copy(line, b)
			fn(line)
		}
		f.Close()
	}
}

// parseAuditTime accepts RFC3339 ("2006-01-02T15:04:05Z") or date-only
// ("2006-01-02", interpreted as midnight UTC).
func parseAuditTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expected RFC3339 (e.g. 2026-06-05T12:00:00Z) or YYYY-MM-DD")
}
