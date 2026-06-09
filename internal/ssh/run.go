// Package ssh opens the connection to the host (direct or through one or more
// bastions) using ephemeral certificates and executes commands. It is the only
// point in the system where credential material exists.
package ssh

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// A3 limits: execution timeout and maximum output size.
const (
	// defaultExecTimeout caps the wait for a one-shot SSH command.
	// Prevents session.Run() from blocking indefinitely.
	defaultExecTimeout = 10 * time.Minute
	// maxOutputBytes is the maximum output buffer size per stream
	// (stdout or stderr). Prevents OOM from arbitrarily large output.
	maxOutputBytes = 10 * 1024 * 1024 // 10 MiB
)

// limitedWriter writes to an internal bytes.Buffer up to max bytes. When the
// limit is exceeded, further writes return an error so the SSH channel stops
// accumulating data.
type limitedWriter struct {
	buf   bytes.Buffer
	max   int
	total int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.total >= lw.max {
		return 0, fmt.Errorf("output truncated: limit of %d bytes exceeded", lw.max)
	}
	rem := lw.max - lw.total
	if len(p) > rem {
		p = p[:rem]
	}
	n, err := lw.buf.Write(p)
	lw.total += n
	return n, err
}

// Hop is one step in the connection chain (bastion or final target). The first
// hop is reached by direct TCP; subsequent hops go through the previous hop's
// channel.
type Hop struct {
	Addr    string
	User    string
	HostKey ssh.PublicKey
	// PrivateKey + Certificate form the signer for this hop's ephemeral cert.
	PrivateKey  ed25519.PrivateKey
	Certificate *ssh.Certificate
}

// Conn wraps the SSH client to the final target and keeps intermediate clients
// so they can be closed in reverse order.
type Conn struct {
	Client  *ssh.Client
	closers []io.Closer
}

// Close closes the final client and the chain of intermediaries.
func (c *Conn) Close() error {
	var firstErr error
	if err := c.Client.Close(); err != nil {
		firstErr = err
	}
	for i := len(c.closers) - 1; i >= 0; i-- {
		if err := c.closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Target describes the destination for a one-shot Run (single hop, no bastion).
type Target struct {
	Addr           string
	User           string
	HostKey        ssh.PublicKey
	ConnectTimeout time.Duration
}

// Result is the captured output of an execution.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func hopClientConfig(h Hop, timeout time.Duration) (*ssh.ClientConfig, error) {
	if h.HostKey == nil {
		return nil, fmt.Errorf("host key for %s is required (do not accept blindly)", h.Addr)
	}
	keySigner, err := ssh.NewSignerFromKey(h.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key signer (%s): %w", h.Addr, err)
	}
	certSigner, err := ssh.NewCertSigner(h.Certificate, keySigner)
	if err != nil {
		return nil, fmt.Errorf("certificate signer (%s): %w", h.Addr, err)
	}
	return &ssh.ClientConfig{
		User:              h.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback:   ssh.FixedHostKey(h.HostKey),
		HostKeyAlgorithms: []string{h.HostKey.Type()},
		Timeout:           timeout,
	}, nil
}

// Dial establishes the connection chain. hops[0] is the first hop (or the
// target if there is no bastion); the last hop is the final target.
func Dial(hops []Hop, timeout time.Duration) (*Conn, error) {
	if len(hops) == 0 {
		return nil, fmt.Errorf("at least one hop is required")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	cfg0, err := hopClientConfig(hops[0], timeout)
	if err != nil {
		return nil, err
	}
	tcp, err := net.DialTimeout("tcp", hops[0].Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", hops[0].Addr, err)
	}
	c0, chans, reqs, err := ssh.NewClientConn(tcp, hops[0].Addr, cfg0)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("handshake %s: %w", hops[0].Addr, err)
	}
	current := ssh.NewClient(c0, chans, reqs)

	conn := &Conn{Client: current}
	for i := 1; i < len(hops); i++ {
		cfg, err := hopClientConfig(hops[i], timeout)
		if err != nil {
			conn.closeAll()
			return nil, err
		}
		// direct-tcpip channel through the previous hop.
		nc, err := current.Dial("tcp", hops[i].Addr)
		if err != nil {
			conn.closeAll()
			return nil, fmt.Errorf("hop to %s: %w", hops[i].Addr, err)
		}
		cc, chans, reqs, err := ssh.NewClientConn(nc, hops[i].Addr, cfg)
		if err != nil {
			nc.Close()
			conn.closeAll()
			return nil, fmt.Errorf("handshake %s (via bastion): %w", hops[i].Addr, err)
		}
		// The previous client becomes an intermediate (to be closed at the end).
		conn.closers = append(conn.closers, current)
		current = ssh.NewClient(cc, chans, reqs)
		conn.Client = current
	}
	return conn, nil
}

func (c *Conn) closeAll() {
	_ = c.Client.Close()
	for i := len(c.closers) - 1; i >= 0; i-- {
		_ = c.closers[i].Close()
	}
}

// ExecOptions controls optional parameters for a remote command execution.
type ExecOptions struct {
	// PTY requests a pseudo-terminal before executing the command. Useful for
	// programs that check isatty() or require a real TTY.
	// Note: with PTY, stdout and stderr are merged in Result.Stdout;
	// Result.Stderr will be empty.
	PTY bool
	// Term is the terminal type to announce (default "xterm-256color").
	Term string
	// Rows and Cols are the PTY dimensions (default 40×220).
	Rows uint32
	Cols uint32
	// Timeout caps the remote command wait (A3). 0 = defaultExecTimeout.
	Timeout time.Duration
}

// defaultPTYTerm is the default terminal type.
const defaultPTYTerm = "xterm-256color"

// ExecOnce opens an exec channel over conn, runs command, and captures the
// output. If opts.PTY is true a PTY is requested first; streams are merged.
// A3: execution is bounded by opts.Timeout (or defaultExecTimeout when 0) and
// output is limited to maxOutputBytes per stream to prevent OOM.
func ExecOnce(client *ssh.Client, command string, opts ...ExecOptions) (*Result, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("opening session: %w", err)
	}
	defer session.Close()

	var o ExecOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	execTimeout := o.Timeout
	if execTimeout <= 0 {
		execTimeout = defaultExecTimeout
	}

	res := &Result{}

	if o.PTY {
		term := o.Term
		if term == "" {
			term = defaultPTYTerm
		}
		rows := o.Rows
		if rows == 0 {
			rows = 40
		}
		cols := o.Cols
		if cols == 0 {
			cols = 220
		}
		modes := ssh.TerminalModes{
			ssh.ECHO:          0, // no echo
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty(term, int(rows), int(cols), modes); err != nil {
			return nil, fmt.Errorf("requesting PTY: %w", err)
		}
		// With PTY, stdout and stderr are merged in the PTY stdout channel.
		var combined limitedWriter
		combined.max = maxOutputBytes
		session.Stdout = &combined

		// A3: run session.Run in a goroutine to be able to cap the time.
		type runRes struct{ err error }
		done := make(chan runRes, 1)
		go func() { done <- runRes{err: session.Run(command)} }()

		select {
		case r := <-done:
			res.Stdout = combined.buf.String()
			if r.err != nil {
				if exitErr, ok := r.err.(*ssh.ExitError); ok {
					res.ExitCode = exitErr.ExitStatus()
					return res, nil
				}
				return res, fmt.Errorf("executing command (pty): %w", r.err)
			}
		case <-time.After(execTimeout):
			_ = session.Signal(ssh.SIGTERM)
			return nil, fmt.Errorf("SSH execution timeout (limit: %v)", execTimeout)
		}
		return res, nil
	}

	var stdout, stderr limitedWriter
	stdout.max = maxOutputBytes
	stderr.max = maxOutputBytes
	session.Stdout = &stdout
	session.Stderr = &stderr

	// A3: run session.Run in a goroutine to be able to cap the time.
	type runRes struct{ err error }
	done := make(chan runRes, 1)
	go func() { done <- runRes{err: session.Run(command)} }()

	select {
	case r := <-done:
		res.Stdout = stdout.buf.String()
		res.Stderr = stderr.buf.String()
		if r.err != nil {
			if exitErr, ok := r.err.(*ssh.ExitError); ok {
				res.ExitCode = exitErr.ExitStatus()
				return res, nil
			}
			return res, fmt.Errorf("executing command: %w", r.err)
		}
	case <-time.After(execTimeout):
		_ = session.Signal(ssh.SIGTERM)
		return nil, fmt.Errorf("SSH execution timeout (limit: %v)", execTimeout)
	}
	return res, nil
}

// Run connects in a single shot (one hop, the target) and executes command.
func Run(priv ed25519.PrivateKey, cert *ssh.Certificate, t Target, command string) (*Result, error) {
	conn, err := Dial([]Hop{{
		Addr: t.Addr, User: t.User, HostKey: t.HostKey,
		PrivateKey: priv, Certificate: cert,
	}}, t.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return ExecOnce(conn.Client, command)
}
