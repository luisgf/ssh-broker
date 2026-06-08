package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Notifier avisa a un canal externo de que hay una solicitud de aprobación
// pendiente. La implementación no debe bloquear de forma prolongada.
type Notifier interface {
	Notify(a Approval) error
}

// LogNotifier escribe la solicitud en el log del proceso. Útil en desarrollo y
// como respaldo: el aprobador puede usar `broker-ctl approval list`.
type LogNotifier struct{}

// Notify implementa Notifier.
func (LogNotifier) Notify(a Approval) error {
	log.Printf("[approval] PENDIENTE id=%s caller=%s user=%s host=%s cmd=%q rule=%s",
		a.ID, a.Caller, a.EndUser, a.Host, a.Command, a.Rule)
	return nil
}

// WebhookNotifier hace POST de la solicitud (JSON) a una URL. Pensado para
// integraciones de chat/alertas (Slack-compatible vía un receptor sencillo).
type WebhookNotifier struct {
	URL    string
	client *http.Client
}

// NewWebhookNotifier crea un notificador webhook con timeout corto.
func NewWebhookNotifier(url string) *WebhookNotifier {
	return &WebhookNotifier{URL: url, client: &http.Client{Timeout: 5 * time.Second}}
}

// Notify implementa Notifier.
func (w *WebhookNotifier) Notify(a Approval) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("serializar notificación: %w", err)
	}
	resp, err := w.client.Post(w.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("enviar webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook devolvió %d", resp.StatusCode)
	}
	return nil
}
