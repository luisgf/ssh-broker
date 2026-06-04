// Command mcp-broker expone el broker como servidor MCP sobre stdio. El modelo
// invoca la herramienta ssh_execute(server, command) y recibe solo la salida:
// por cada llamada se firma un certificado SSH efímero y acotado, se ejecuta el
// comando y se audita. El modelo nunca ve clave ni certificado.
//
// Lanzar desde el cliente MCP, p. ej. en ~/.claude.json:
//
//	"ssh-broker": { "type": "stdio", "command": "/ruta/mcp-broker",
//	                "args": ["-config", "/ruta/config.json"] }
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
)

// caller identifica el origen en la auditoría. Sobre stdio el llamante es el
// proceso cliente local que lanzó el broker (no hay mTLS); el aislamiento lo da
// que el proceso lo arranca el propio usuario/cliente MCP.
const caller = "mcp-stdio"

type executeInput struct {
	Server     string `json:"server"               jsonschema:"nombre lógico del host destino (ver ssh_list_servers)"`
	Command    string `json:"command"              jsonschema:"comando a ejecutar en el host"`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"validez del certificado efímero en segundos; omitir para usar el máximo permitido por la política del host"`
	Sudo       bool   `json:"sudo,omitempty"       jsonschema:"si true ejecuta con sudo -n (NOPASSWD). Requiere allow_sudo=true en ssh_list_servers. Si allow_sudo=false NO reintentes: informa al usuario de que el host no permite elevación."`
	SudoUser   string `json:"sudo_user,omitempty"  jsonschema:"usuario destino del sudo (vacío = root). Debe estar en la lista allowed_sudo_users del host."`
	PTY        bool   `json:"pty,omitempty"        jsonschema:"si true solicita un pseudo-terminal (stdout y stderr se mezclan). Requiere allow_pty=true en ssh_list_servers. Usar solo para comandos que necesitan TTY. Si allow_pty=false NO reintentes."`
}

type executeOutput struct {
	Stdout   string `json:"stdout"    jsonschema:"salida estándar del comando remoto"`
	Stderr   string `json:"stderr"    jsonschema:"salida de error del comando remoto (vacío si se usó pty=true, ya que stdout y stderr se mezclan)"`
	ExitCode int    `json:"exit_code" jsonschema:"código de salida del comando remoto: 0=éxito, distinto de 0=fallo del comando (NO es un error de la tool)"`
	Serial   uint64 `json:"serial"    jsonschema:"identificador de auditoría; ignorar para razonar sobre el resultado"`
}

type listInput struct{}

type serverEntry struct {
	Name      string `json:"name"`
	AllowSudo bool   `json:"allow_sudo"`
	AllowPTY  bool   `json:"allow_pty"`
	Jump      string `json:"jump,omitempty"`
}

type listOutput struct {
	Servers []serverEntry `json:"servers"`
}

type sessionOpenInput struct {
	Server     string `json:"server"               jsonschema:"nombre lógico del host destino (ver ssh_list_servers)"`
	Mode       string `json:"mode,omitempty"       jsonschema:"exec (por defecto): comandos aislados sin estado compartido. shell: sh persistente, cd y variables de entorno sobreviven entre ssh_session_exec. pty: shell con pseudo-terminal para programas interactivos (editores, less, etc.); requiere allow_pty=true. Si allow_pty=false NO uses pty."`
	TTLSeconds int    `json:"ttl_seconds,omitempty" jsonschema:"validez del certificado de conexión en segundos; omitir para usar el máximo permitido por la política del host"`
	Sudo       bool   `json:"sudo,omitempty"       jsonschema:"si true arranca con elevación sudo -n (NOPASSWD). En mode=shell/pty eleva el proceso shell completo. En mode=exec antepone sudo a cada comando individual. Requiere allow_sudo=true en ssh_list_servers. Si allow_sudo=false NO reintentes."`
	SudoUser   string `json:"sudo_user,omitempty"  jsonschema:"usuario destino del sudo (vacío = root). Debe estar en la lista allowed_sudo_users del host."`
}

type sessionExecInput struct {
	SessionID string `json:"session_id" jsonschema:"id devuelto por ssh_session_open"`
	Command   string `json:"command"    jsonschema:"comando a ejecutar en la sesión"`
}

type sessionCloseInput struct {
	SessionID string `json:"session_id" jsonschema:"id de la sesión a cerrar"`
}

type okOutput struct {
	OK bool `json:"ok"`
}

func main() {
	cfgPath := flag.String("config", "config.json", "ruta al fichero de configuración JSON")
	flag.Parse()

	cfg, err := broker.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	eng, err := broker.NewEngine(cfg)
	if err != nil {
		log.Fatalf("inicializar broker: %v", err)
	}
	defer eng.Close()

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "ssh-broker",
		Title:   "SSH Broker (CA efímera)",
		Version: "1.2.0",
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_execute",
		Description: "Ejecuta un único comando en un host Linux vía SSH con credencial efímera. " +
			"Preferir esta tool frente a ssh_session_open cuando solo se necesita ejecutar un comando o comandos independientes entre sí. " +
			"Devuelve stdout, stderr y exit_code. " +
			"exit_code != 0 indica fallo del comando remoto, NO un error de la tool; tratar igual que un proceso que termina con error. " +
			"ANTES de llamar: usar ssh_list_servers para conocer las capacidades del host. " +
			"sudo=true SOLO si allow_sudo=true; si allow_sudo=false, NO reintentar con sudo e informar al usuario. " +
			"pty=true SOLO si allow_pty=true y el comando necesita TTY (con pty stdout y stderr se mezclan). " +
			"ttl_seconds es opcional; omitir para usar el máximo que permita la política del host.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in executeInput) (*mcp.CallToolResult, executeOutput, error) {
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser, PTY: in.PTY}
		res, err := eng.Execute(caller, in.Server, in.Command, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
			}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_list_servers",
		Description: "Lista los hosts configurados en el broker con sus capacidades. " +
			"Llamar SIEMPRE antes de ssh_execute o ssh_session_open. " +
			"Campos por host: " +
			"allow_sudo=true → el host acepta elevación sudo NOPASSWD (se puede usar sudo=true); " +
			"allow_sudo=false → NO intentar sudo, el signer lo rechazará. " +
			"allow_pty=true → el host acepta PTY (se puede usar pty=true o mode=pty); " +
			"allow_pty=false → NO intentar PTY. " +
			"jump → nombre del bastión por el que se alcanza el host (informativo).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listInput) (*mcp.CallToolResult, listOutput, error) {
		infos := eng.ServerInfos()
		entries := make([]serverEntry, len(infos))
		var sb strings.Builder
		for i, s := range infos {
			entries[i] = serverEntry{Name: s.Name, AllowSudo: s.AllowSudo, AllowPTY: s.AllowPTY, Jump: s.Jump}
			fmt.Fprintf(&sb, "%s (sudo=%v pty=%v", s.Name, s.AllowSudo, s.AllowPTY)
			if s.Jump != "" {
				fmt.Fprintf(&sb, " via=%s", s.Jump)
			}
			sb.WriteString(")\n")
		}
		out := listOutput{Servers: entries}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ssh_session_open",
		Description: "Abre una sesión SSH persistente que reutiliza la conexión entre comandos. " +
			"Usar cuando se necesiten varios comandos con estado compartido (ej. cd a un directorio y luego operar en él) o programas interactivos. " +
			"Para comandos aislados preferir ssh_execute (más simple y con mayor garantía de aislamiento). " +
			"Modos disponibles: exec (por defecto, comandos independientes), shell (sh con estado: cd y variables persisten), pty (shell con TTY para programas interactivos). " +
			"sudo=true SOLO si allow_sudo=true (ver ssh_list_servers); si allow_sudo=false NO reintentar. " +
			"mode=pty SOLO si allow_pty=true. " +
			"Devuelve session_id para usar con ssh_session_exec. " +
			"IMPORTANTE: cerrar siempre la sesión con ssh_session_close al terminar; las sesiones consumen recursos y expiran por TTL.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionOpenInput) (*mcp.CallToolResult, sessionOpenOutput, error) {
		opts := broker.ExecOptions{Sudo: in.Sudo, SudoUser: in.SudoUser}
		r, err := eng.OpenSession(caller, in.Server, in.Mode, in.TTLSeconds, opts)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, sessionOpenOutput{}, nil
		}
		out := sessionOpenOutput{SessionID: r.SessionID, Serial: r.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("session_id=%s serial=%d", r.SessionID, r.Serial)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ssh_session_exec",
		Description: "Ejecuta un comando en una sesión abierta con ssh_session_open. " +
			"Devuelve stdout, stderr y exit_code. " +
			"exit_code != 0 indica fallo del comando remoto, NO un error de la tool. " +
			"El estado de la sesión (directorio actual, variables de entorno) persiste entre llamadas si mode=shell o mode=pty.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionExecInput) (*mcp.CallToolResult, executeOutput, error) {
		res, err := eng.SessionExec(caller, in.SessionID, in.Command)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, executeOutput{}, nil
		}
		out := executeOutput{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode, Serial: res.Serial}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderResult(out)}}}, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ssh_session_close",
		Description: "Cierra una sesión SSH persistente y libera la conexión. " +
			"Llamar siempre al terminar de trabajar con una sesión; no cerrarla consume recursos hasta que expira el TTL del certificado.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sessionCloseInput) (*mcp.CallToolResult, okOutput, error) {
		if err := eng.CloseSession(caller, in.SessionID); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, okOutput{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "cerrada"}}}, okOutput{OK: true}, nil
	})

	log.Printf("mcp-broker (stdio) listo; %d hosts configurados", len(eng.Servers()))
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("servidor MCP: %v", err)
	}
}

// sessionOpenOutput debe estar definido aquí para que mcp.AddTool lo use como tipo de retorno.
type sessionOpenOutput struct {
	SessionID string `json:"session_id"`
	Serial    uint64 `json:"serial"`
}

func renderResult(o executeOutput) string {
	var b strings.Builder
	if o.Stdout != "" {
		b.WriteString(o.Stdout)
	}
	if o.Stderr != "" {
		fmt.Fprintf(&b, "\n[stderr]\n%s", o.Stderr)
	}
	fmt.Fprintf(&b, "\n[exit=%d serial=%d]", o.ExitCode, o.Serial)
	return b.String()
}
