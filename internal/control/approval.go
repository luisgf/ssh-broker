// Package control implementa el control plane: un Policy Enforcement Point que se
// sitúa entre el broker y el signer. Orquesta la aprobación humana de comandos
// (human-in-the-loop) y los guardrails de comportamiento, SIN custodiar la clave
// de CA (que permanece en el signer). El signer aplica la política autoritativa;
// el control plane decide cuándo una operación necesita aprobación y la gestiona.
package control

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/luisgf/ssh-broker/internal/signer"
)

// Status es el estado de una solicitud de aprobación.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Approval es una solicitud de aprobación humana para una operación que la
// command policy marcó como require_approval.
type Approval struct {
	ID        string    `json:"id"`
	Caller    string    `json:"caller"`             // CN del broker que originó la petición
	EndUser   string    `json:"end_user,omitempty"` // identidad OIDC del usuario final
	Host      string    `json:"host"`
	Command   string    `json:"command"`
	Sudo      bool      `json:"sudo,omitempty"`
	SudoUser  string    `json:"sudo_user,omitempty"`
	Rule      string    `json:"rule,omitempty"` // regla require_approval que casó
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitempty"`

	// req es la petición original a reenviar al signer una vez aprobada. No se
	// serializa hacia el exterior (contiene la pubkey efímera).
	req signer.WireRequest
	// consumed evita que una única aprobación emita más de un certificado.
	consumed bool
}

// Registry mantiene las solicitudes de aprobación en memoria con expiración por TTL.
type Registry struct {
	mu    sync.Mutex
	items map[string]*Approval
	ttl   time.Duration
}

// NewRegistry crea un registro con el TTL dado para las solicitudes pendientes.
func NewRegistry(ttl time.Duration) *Registry {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &Registry{items: make(map[string]*Approval), ttl: ttl}
}

// Create registra una nueva solicitud pendiente a partir de la petición y la
// decisión de política. Devuelve la solicitud creada (con ID asignado).
func (r *Registry) Create(req signer.WireRequest, caller string, dec *signer.DecisionInfo) (*Approval, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	a := &Approval{
		ID:        id,
		Caller:    caller,
		EndUser:   req.EndUser,
		Host:      req.Host,
		Command:   req.Command,
		Sudo:      req.Sudo,
		SudoUser:  req.SudoUser,
		Status:    StatusPending,
		CreatedAt: time.Now().UTC(),
		req:       req,
	}
	if dec != nil {
		a.Rule = dec.MatchedRule
	}
	r.mu.Lock()
	r.items[id] = a
	r.mu.Unlock()
	return a, nil
}

// Get devuelve una copia de la solicitud, aplicando expiración perezosa.
func (r *Registry) Get(id string) (Approval, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return Approval{}, false
	}
	r.expireLocked(a)
	return *a, true
}

// Request devuelve la WireRequest original (para reenviar al signer tras aprobar).
func (r *Registry) Request(id string) (signer.WireRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return signer.WireRequest{}, false
	}
	return a.req, true
}

// Decide resuelve una solicitud pendiente como aprobada o denegada. Falla si la
// solicitud no existe o ya no está pendiente (expirada/resuelta).
func (r *Registry) Decide(id string, approve bool, by string) (Approval, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return Approval{}, fmt.Errorf("solicitud de aprobación desconocida: %q", id)
	}
	r.expireLocked(a)
	if a.Status != StatusPending {
		return *a, fmt.Errorf("la solicitud %q ya no está pendiente (estado: %s)", id, a.Status)
	}
	if approve {
		a.Status = StatusApproved
	} else {
		a.Status = StatusDenied
	}
	a.DecidedBy = by
	a.DecidedAt = time.Now().UTC()
	return *a, nil
}

// Consume marca una solicitud aprobada como ya emitida. Devuelve true solo la
// primera vez (estado aprobado y no consumida); en otro caso false. Evita que una
// sola aprobación se reutilice para emitir varios certificados.
func (r *Registry) Consume(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.items[id]
	if !ok {
		return false
	}
	r.expireLocked(a)
	if a.Status != StatusApproved || a.consumed {
		return false
	}
	a.consumed = true
	return true
}

// List devuelve una copia de todas las solicitudes (aplicando expiración).
func (r *Registry) List() []Approval {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Approval, 0, len(r.items))
	for _, a := range r.items {
		r.expireLocked(a)
		out = append(out, *a)
	}
	return out
}

// expireLocked marca como expirada una solicitud pendiente cuyo TTL ha vencido.
// Debe llamarse con r.mu retenido.
func (r *Registry) expireLocked(a *Approval) {
	if a.Status == StatusPending && time.Since(a.CreatedAt) > r.ttl {
		a.Status = StatusExpired
	}
}

// newID genera un identificador hexadecimal aleatorio de 128 bits.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generar id de aprobación: %w", err)
	}
	return hex.EncodeToString(b), nil
}
