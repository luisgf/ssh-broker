package signer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// WireRequest es el cuerpo de POST /v1/sign. No incluye Caller: el servicio lo
// deriva del certificado de cliente mTLS (no es asertable por el broker).
type WireRequest struct {
	Host       string `json:"host"`
	Role       string `json:"role"`
	Purpose    string `json:"purpose"`
	Command    string `json:"command,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	PublicKey  string `json:"public_key"` // línea authorized_keys de la pubkey efímera

	// Elevación (sudo NOPASSWD).
	Sudo     bool   `json:"sudo,omitempty"`
	SudoUser string `json:"sudo_user,omitempty"` // vacío = root

	// PTY: solicita permit-pty en el certificado.
	PTY bool `json:"pty,omitempty"`

	// DryRun: resuelve la política y devuelve la decisión sin emitir cert usable.
	DryRun bool `json:"dry_run,omitempty"`

	// OnBehalfOf: CN del broker en cuyo nombre actúa un forwarder de confianza
	// (control plane). El signer lo honra solo si el CN mTLS está en trusted_forwarders.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`

	// Approved: la operación (que requiere aprobación) ya fue aprobada. Honrado solo
	// desde un forwarder de confianza.
	Approved bool `json:"approved,omitempty"`

	// Identidad del usuario final, aseverada por el broker (autenticado por mTLS).
	// EndUser alimenta la trazabilidad; EndUserGroups, si no es nil, activa el RBAC
	// por usuario en el signer.
	EndUser       string   `json:"end_user,omitempty"`
	EndUserGroups []string `json:"end_user_groups,omitempty"`
}

// WireResponse es la respuesta del servicio a /v1/sign.
type WireResponse struct {
	Certificate string `json:"certificate,omitempty"` // línea authorized_keys del cert (vacío en dry-run)
	Serial      uint64 `json:"serial,omitempty"`
	// ElevationPrefix es el prefijo a anteponer en sesiones persistentes.
	// Vacío en one-shot (el prefijo ya está en el force-command del cert).
	ElevationPrefix string `json:"elevation_prefix,omitempty"`
	// Decision se rellena en dry-run (Certificate vacío) y, opcionalmente, en
	// emisión normal para trazabilidad.
	Decision *DecisionInfo `json:"decision,omitempty"`
}

// WireHostInfo contiene los datos de conectividad y capacidades de un host,
// tal como los devuelve GET /v1/hosts. No incluye datos de política internos
// (principal, source_address, etc.) — esos son exclusivos del signer.
type WireHostInfo struct {
	Addr    string `json:"addr"`
	User    string `json:"user"`
	HostKey string `json:"host_key"`
	Jump    string `json:"jump,omitempty"`
	// Capacidades: indica al broker (y al modelo) qué operaciones están permitidas.
	AllowSudo bool `json:"allow_sudo,omitempty"`
	AllowPTY  bool `json:"allow_pty,omitempty"`
}

// HostInfo es la representación interna del broker de los datos de
// conectividad y capacidades recibidos del signer.
type HostInfo struct {
	Addr      string
	User      string
	HostKey   string
	Jump      string
	AllowSudo bool
	AllowPTY  bool
}

// Remote delega la firma en el servicio externo por HTTP+mTLS. Sirve tanto para
// hablar con el signer directamente como con el control plane (mismo protocolo);
// en este último caso una respuesta 202 indica que la operación quedó pendiente de
// aprobación humana y se hace polling hasta resolverla.
type Remote struct {
	client       *http.Client
	url          string
	approvalWait time.Duration // tiempo máximo de espera ante un 202 (0 = no esperar)
}

// NewRemote crea un cliente del servicio de firma.
func NewRemote(url string, tlsCfg *tls.Config, timeout time.Duration) *Remote {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Remote{
		url:    url,
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}
}

// SetApprovalWait fija cuánto espera el cliente a que se resuelva una aprobación
// humana (respuesta 202 del control plane). 0 = no esperar (un 202 se traduce en
// error inmediato).
func (r *Remote) SetApprovalWait(d time.Duration) { r.approvalWait = d }

// SignIntent implementa Signer contra el servicio remoto.
func (r *Remote) SignIntent(in Intent) (*Issued, error) {
	body, err := json.Marshal(WireRequest{
		Host:          in.Host,
		Role:          in.Role,
		Purpose:       in.Purpose,
		Command:       in.Command,
		TTLSeconds:    int(in.RequestedTTL / time.Second),
		PublicKey:     string(ssh.MarshalAuthorizedKey(in.PublicKey)),
		Sudo:          in.Sudo,
		SudoUser:      in.SudoUser,
		PTY:           in.PTY,
		DryRun:        in.DryRun,
		OnBehalfOf:    in.OnBehalfOf,
		Approved:      in.Approved,
		EndUser:       in.EndUser,
		EndUserGroups: in.EndUserGroups,
	})
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Post(r.url+"/v1/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("contactar servicio de firma: %w", err)
	}
	defer resp.Body.Close()
	// A2: limitar la lectura de /v1/sign para evitar OOM por respuestas gigantes.
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("leer respuesta de /v1/sign: %w", err)
	}
	// 202: la operación requiere aprobación humana (control plane). Hacer polling.
	if resp.StatusCode == http.StatusAccepted {
		var acc struct {
			ApprovalID string `json:"approval_id"`
		}
		if err := json.Unmarshal(rb, &acc); err != nil || acc.ApprovalID == "" {
			return nil, fmt.Errorf("respuesta 202 inválida del control plane")
		}
		return r.pollApproval(acc.ApprovalID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("firma rechazada (%d): %s", resp.StatusCode, bytes.TrimSpace(rb))
	}

	var wr WireResponse
	if err := json.Unmarshal(rb, &wr); err != nil {
		return nil, fmt.Errorf("respuesta inválida: %w", err)
	}
	// Dry-run, o respuesta sin certificado (requiere aprobación): solo la decisión.
	if in.DryRun || wr.Certificate == "" {
		return &Issued{Decision: wr.Decision}, nil
	}
	cert, err := ParseCertificate(wr.Certificate)
	if err != nil {
		return nil, err
	}
	return &Issued{Certificate: cert, Serial: wr.Serial, ElevationPrefix: wr.ElevationPrefix, Decision: wr.Decision}, nil
}

// HeaderOnBehalfOf transporta el CN del broker en peticiones GET (sin cuerpo) que
// un forwarder de confianza (control plane) hace en su nombre.
const HeaderOnBehalfOf = "X-On-Behalf-Of"

// pollApproval consulta GET /v1/sign/result/{id} hasta que la solicitud se
// resuelve (cert emitido tras aprobación), se deniega/expira, o se agota
// approvalWait. Cada poll es una petición corta; el intervalo entre polls es fijo.
func (r *Remote) pollApproval(approvalID string) (*Issued, error) {
	if r.approvalWait <= 0 {
		return nil, fmt.Errorf("la operación requiere aprobación humana (id %s); el cliente no está configurado para esperar", approvalID)
	}
	const interval = 2 * time.Second
	deadline := time.Now().Add(r.approvalWait)
	for {
		time.Sleep(interval)
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("aprobación no concedida dentro del plazo (id %s)", approvalID)
		}
		resp, err := r.client.Get(r.url + "/v1/sign/result/" + approvalID)
		if err != nil {
			return nil, fmt.Errorf("consultar resultado de aprobación: %w", err)
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusAccepted:
			continue // sigue pendiente
		case http.StatusOK:
			var wr WireResponse
			if err := json.Unmarshal(rb, &wr); err != nil {
				return nil, fmt.Errorf("respuesta de aprobación inválida: %w", err)
			}
			cert, err := ParseCertificate(wr.Certificate)
			if err != nil {
				return nil, err
			}
			return &Issued{Certificate: cert, Serial: wr.Serial, ElevationPrefix: wr.ElevationPrefix, Decision: wr.Decision}, nil
		default:
			return nil, fmt.Errorf("aprobación no concedida (%d): %s", resp.StatusCode, bytes.TrimSpace(rb))
		}
	}
}

// FetchHosts llama a GET /v1/hosts en el signer y devuelve los datos de
// conectividad de todos los hosts configurados. El broker usa esta información
// para construir los hops SSH; la política de firma permanece en el signer.
//
// onBehalfOf, si no es vacío, se envía en la cabecera X-On-Behalf-Of para que el
// signer filtre los hosts por los grupos del broker original (uso del control
// plane). El broker pasa "" (actúa en su propio nombre).
func (r *Remote) FetchHosts(onBehalfOf string) (map[string]HostInfo, error) {
	req, err := http.NewRequest(http.MethodGet, r.url+"/v1/hosts", nil)
	if err != nil {
		return nil, fmt.Errorf("construir petición /v1/hosts: %w", err)
	}
	if onBehalfOf != "" {
		req.Header.Set(HeaderOnBehalfOf, onBehalfOf)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("obtener lista de hosts: %w", err)
	}
	defer resp.Body.Close()
	// A2: limitar la lectura de /v1/hosts para evitar OOM por respuestas gigantes.
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("leer respuesta de /v1/hosts: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer devolvió %d: %s", resp.StatusCode, bytes.TrimSpace(rb))
	}

	var wire map[string]WireHostInfo
	if err := json.Unmarshal(rb, &wire); err != nil {
		return nil, fmt.Errorf("respuesta /v1/hosts inválida: %w", err)
	}

	hosts := make(map[string]HostInfo, len(wire))
	for name, h := range wire {
		hosts[name] = HostInfo{
			Addr:      h.Addr,
			User:      h.User,
			HostKey:   h.HostKey,
			Jump:      h.Jump,
			AllowSudo: h.AllowSudo,
			AllowPTY:  h.AllowPTY,
		}
	}
	return hosts, nil
}

// ParseCertificate convierte una línea authorized_keys en *ssh.Certificate.
func ParseCertificate(authorizedLine string) (*ssh.Certificate, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if err != nil {
		return nil, fmt.Errorf("parsear certificado: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("la clave devuelta no es un certificado")
	}
	return cert, nil
}

// ParsePublicKey convierte una línea authorized_keys en ssh.PublicKey.
func ParsePublicKey(authorizedLine string) (ssh.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedLine))
	if err != nil {
		return nil, fmt.Errorf("parsear pubkey: %w", err)
	}
	return pk, nil
}
