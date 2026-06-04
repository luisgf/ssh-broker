// Command mcp-broker expone el broker como servidor MCP sobre stdio. El modelo
// invoca la herramienta ssh_execute(server, command) y recibe solo la salida:
// por cada llamada se firma un certificado SSH efímero y acotado, se ejecuta el
// comando y se audita. El modelo nunca ve clave ni certificado.
//
// Lanzar desde el cliente MCP, p. ej. en ~/.claude.json:
//
//	"ssh-broker": { "type": "stdio", "command": "/ruta/mcp-broker",
//	                "args": ["-config", "/ruta/config.json"] }
//
// Para exponer el broker por red con autenticación OAuth2/OIDC, ver
// cmd/mcp-broker-http.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
	"github.com/luisgf/ssh-broker/internal/mcpserver"
)

// stdioCaller identifica el origen en la auditoría. Sobre stdio el llamante es el
// proceso cliente local que lanzó el broker (no hay mTLS ni OAuth); el aislamiento
// lo da que el proceso lo arranca el propio usuario/cliente MCP. Sin grupos: el
// signer no aplica RBAC por usuario para peticiones locales.
func stdioCaller(context.Context) broker.Caller {
	return broker.Caller{ID: "mcp-stdio"}
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

	srv := mcpserver.New(eng, stdioCaller)

	log.Printf("mcp-broker (stdio) listo; %d hosts configurados", len(eng.Servers()))
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("servidor MCP: %v", err)
	}
}
