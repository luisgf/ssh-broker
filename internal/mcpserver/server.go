package mcpserver

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/luisgf/ssh-broker/internal/broker"
)

// Version is the version announced by the MCP server to its clients.
const Version = "1.4.1"

// New builds a *mcp.Server with the broker tools registered. callerFn
// determines the caller identity per request (fixed in stdio, derived from the
// OIDC token in HTTP).
func New(eng *broker.Engine, callerFn CallerFunc) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "ssh-broker",
		Title:   "SSH Broker (ephemeral CA)",
		Version: Version,
	}, nil)
	Register(srv, eng, callerFn)
	return srv
}
