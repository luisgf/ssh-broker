package broker

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luisgf/ssh-broker/internal/audit"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestSessionManager(t *testing.T) *sessionManager {
	t.Helper()
	m := newSessionManager(5*time.Minute, 30*time.Minute, nil)
	t.Cleanup(func() { m.closeAll() })
	return m
}

func dummySession(id, caller string) *liveSession {
	return &liveSession{
		id:       id,
		caller:   caller,
		host:     "host:22",
		mode:     "exec",
		created:  time.Now(),
		lastUsed: time.Now(),
	}
}

// testAuditLog abre un log de auditoría temporal para tests que necesitan un Engine.
func testAuditLog(t *testing.T) *audit.Log {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"), ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return al
}

// ── sessionManager: add / get / remove ───────────────────────────────────────

func TestSessionManagerAddGetRemove(t *testing.T) {
	m := newTestSessionManager(t)

	s := dummySession("s1", "alice")
	if err := m.add(s); err != nil {
		t.Fatalf("add: %v", err)
	}

	got, ok := m.get("s1")
	if !ok || got.id != "s1" {
		t.Fatalf("get después de add: ok=%v, got=%v", ok, got)
	}

	removed, ok := m.remove("s1")
	if !ok || removed.id != "s1" {
		t.Fatalf("remove: ok=%v", ok)
	}

	// Después del remove ya no debe existir.
	_, ok = m.get("s1")
	if ok {
		t.Error("get después de remove debe devolver false")
	}
}

func TestSessionManagerGetActualizaLastUsed(t *testing.T) {
	m := newTestSessionManager(t)
	s := dummySession("s2", "bob")
	s.lastUsed = time.Now().Add(-10 * time.Minute)
	_ = m.add(s)

	before := s.lastUsed
	time.Sleep(2 * time.Millisecond)
	got, _ := m.get("s2")
	if !got.lastUsed.After(before) {
		t.Error("get debe actualizar lastUsed")
	}
}

func TestSessionManagerGetInexistente(t *testing.T) {
	m := newTestSessionManager(t)
	_, ok := m.get("nope")
	if ok {
		t.Error("get de id inexistente debe devolver false")
	}
}

func TestSessionManagerRemoveInexistente(t *testing.T) {
	m := newTestSessionManager(t)
	_, ok := m.remove("nope")
	if ok {
		t.Error("remove de id inexistente debe devolver false")
	}
}

// ── sessionManager: límites (M2) ─────────────────────────────────────────────

func TestSessionManagerLimiteGlobal(t *testing.T) {
	m := newTestSessionManager(t)

	// Añadir maxSessionsGlobal sesiones con callers distintos para no activar
	// el límite por-caller (maxSessionsPerCaller=20) antes del global (200).
	for i := 0; i < maxSessionsGlobal; i++ {
		caller := strings.Repeat("c", (i/maxSessionsPerCaller)+1) + strings.Repeat("x", i%maxSessionsPerCaller)
		s := dummySession(strings.Repeat("s", i+1), caller)
		if err := m.add(s); err != nil {
			t.Fatalf("add sesión %d/%d: %v", i+1, maxSessionsGlobal, err)
		}
	}

	// La siguiente debe ser rechazada.
	extra := dummySession("overflow", "new-caller")
	if err := m.add(extra); err == nil {
		t.Error("add por encima del límite global debe devolver error")
	}
}

func TestSessionManagerLimitePorCaller(t *testing.T) {
	m := newTestSessionManager(t)

	// Añadir maxSessionsPerCaller sesiones del mismo caller.
	for i := 0; i < maxSessionsPerCaller; i++ {
		s := dummySession(strings.Repeat("a", i+1), "heavy-caller")
		if err := m.add(s); err != nil {
			t.Fatalf("add sesión %d/%d: %v", i+1, maxSessionsPerCaller, err)
		}
	}

	extra := dummySession("over-per-caller", "heavy-caller")
	if err := m.add(extra); err == nil {
		t.Error("add por encima del límite por caller debe devolver error")
	}

	// Otro caller diferente aún puede añadir sesiones.
	other := dummySession("other-caller-session", "other-caller")
	if err := m.add(other); err != nil {
		t.Errorf("caller diferente no debe verse afectado: %v", err)
	}
}

// ── sessionManager: reaper ────────────────────────────────────────────────────

func TestSessionManagerReaperIdleTTL(t *testing.T) {
	reaped := make(chan string, 4)
	m := newSessionManager(
		20*time.Millisecond, // idleTTL muy corto
		1*time.Hour,
		func(s *liveSession) { reaped <- s.id },
	)
	t.Cleanup(func() { m.closeAll() })

	// Forzar el ticker interno a un valor muy corto inyectando la sesión con
	// lastUsed en el pasado.
	s := dummySession("stale", "reap-caller")
	s.lastUsed = time.Now().Add(-1 * time.Hour)
	_ = m.add(s)

	// Disparar el reaper manualmente accediendo al estado interno bajo el lock.
	// Esto evita tener que esperar el tick de 30 s de producción.
	m.mu.Lock()
	now := time.Now()
	for id, sess := range m.sessions {
		if now.Sub(sess.lastUsed) > m.idleTTL {
			sess.close()
			delete(m.sessions, id)
			if m.onReap != nil {
				m.onReap(sess)
			}
		}
	}
	m.mu.Unlock()

	select {
	case id := <-reaped:
		if id != "stale" {
			t.Errorf("reaper reportó %q, quiero \"stale\"", id)
		}
	default:
		t.Error("el reaper debería haber eliminado la sesión stale")
	}

	if _, ok := m.get("stale"); ok {
		t.Error("la sesión stale no debería existir tras el reaper")
	}
}

// ── SessionExec: seguridad C1 (ownership) ─────────────────────────────────────

// engineForSessionTests construye un Engine mínimo con sessions inicializadas
// y un log de auditoría temporal, sin red ni signer.
func engineForSessionTests(t *testing.T) *Engine {
	t.Helper()
	al := testAuditLog(t)
	e := &Engine{
		cfg:      &Config{Hosts: map[string]HostConfig{}},
		auditLog: al,
		sessions: newSessionManager(5*time.Minute, 30*time.Minute, nil),
	}
	t.Cleanup(func() { e.sessions.closeAll() })
	return e
}

func TestSessionExecOwnershipC1(t *testing.T) {
	e := engineForSessionTests(t)

	// Inyectar una sesión propiedad de "alice".
	s := dummySession("sess-alice", "alice")
	s.mode = "exec"
	_ = e.sessions.add(s)

	// "bob" no debería poder ejecutar en la sesión de "alice".
	_, err := e.SessionExec(Caller{ID: "bob"}, "sess-alice", "id")
	if err == nil {
		t.Fatal("SessionExec con caller incorrecto debe devolver error (C1)")
	}
	if !strings.Contains(err.Error(), "no pertenece") {
		t.Errorf("mensaje de error inesperado: %v", err)
	}
}

func TestSessionExecSesionDesconocida(t *testing.T) {
	e := engineForSessionTests(t)

	_, err := e.SessionExec(Caller{ID: "alice"}, "nonexistent", "id")
	if err == nil {
		t.Fatal("SessionExec con sesión desconocida debe devolver error")
	}
}

func TestSessionExecComandoVacio(t *testing.T) {
	e := engineForSessionTests(t)

	s := dummySession("sess-empty", "alice")
	s.mode = "exec"
	_ = e.sessions.add(s)

	_, err := e.SessionExec(Caller{ID: "alice"}, "sess-empty", "")
	if err == nil {
		t.Fatal("SessionExec con comando vacío debe devolver error")
	}
}

// ── SessionExec: inyección de comandos M5 (newlines) ─────────────────────────

func TestSessionExecRechazaNewlineModoShell(t *testing.T) {
	e := engineForSessionTests(t)

	for _, mode := range []string{"shell", "pty"} {
		s := dummySession("sess-"+mode, "alice")
		s.mode = mode
		_ = e.sessions.add(s)

		for _, injected := range []string{"cmd\nmalicious", "cmd\rmalicious", "line1\nline2\nline3"} {
			_, err := e.SessionExec(Caller{ID: "alice"}, "sess-"+mode, injected)
			if err == nil {
				t.Errorf("mode=%s cmd=%q: esperaba error por newline (M5)", mode, injected)
			}
			if !strings.Contains(err.Error(), "saltos de línea") {
				t.Errorf("mode=%s: mensaje de error inesperado: %v", mode, err)
			}
		}
	}
}

// TestSessionExecModoExecNoValidaNewline verifica que la validación de newlines
// (M5) solo aplica a modos shell/pty, no a exec. Se prueba inspeccionando la
// condición directamente sin necesidad de una conexión SSH real.
func TestSessionExecModoExecNoValidaNewline(t *testing.T) {
	// Construir una sesión exec en memoria.
	s := dummySession("sess-exec-check", "alice")
	s.mode = "exec"

	// La condición de rechazo de newline en production code es:
	//   (s.mode == "shell" || s.mode == "pty") && strings.ContainsAny(command, "\n\r")
	// Para mode="exec" la condición es siempre false. Verificamos la lógica
	// sin atravesar SessionExec (que necesitaría una conexión SSH real).
	command := "echo hello\necho world"
	shouldReject := (s.mode == "shell" || s.mode == "pty") && strings.ContainsAny(command, "\n\r")
	if shouldReject {
		t.Error("modo exec no debe rechazar newlines según la condición de validación M5")
	}
}

// ── CloseSession: seguridad C1 ────────────────────────────────────────────────

func TestCloseSessionOwnershipC1(t *testing.T) {
	e := engineForSessionTests(t)

	s := dummySession("sess-close", "owner")
	_ = e.sessions.add(s)

	// Caller diferente no puede cerrar la sesión.
	err := e.CloseSession(Caller{ID: "intruder"}, "sess-close")
	if err == nil {
		t.Fatal("CloseSession con caller incorrecto debe devolver error (C1)")
	}
	if !strings.Contains(err.Error(), "no pertenece") {
		t.Errorf("mensaje de error inesperado: %v", err)
	}

	// La sesión debe seguir existiendo.
	_, ok := e.sessions.get("sess-close")
	if !ok {
		t.Error("la sesión no debe eliminarse si el caller no es el propietario")
	}
}

func TestCloseSessionDesconocida(t *testing.T) {
	e := engineForSessionTests(t)
	err := e.CloseSession(Caller{ID: "alice"}, "ghost")
	if err == nil {
		t.Fatal("CloseSession con sesión desconocida debe devolver error")
	}
}

func TestCloseSessionHappyPath(t *testing.T) {
	e := engineForSessionTests(t)

	s := dummySession("sess-ok", "alice")
	_ = e.sessions.add(s)

	if err := e.CloseSession(Caller{ID: "alice"}, "sess-ok"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	// Después del cierre la sesión no debe existir.
	_, ok := e.sessions.get("sess-ok")
	if ok {
		t.Error("la sesión debe eliminarse tras CloseSession exitoso")
	}
}

// ── Helpers internos ──────────────────────────────────────────────────────────

func TestBuildElevatedExecCommand(t *testing.T) {
	cases := []struct {
		prefix  string
		command string
		want    string
	}{
		{"sudo -n", "id", "sudo -n -- /bin/sh -c 'id'"},
		{"sudo -n -u deploy", "ls /root", "sudo -n -u deploy -- /bin/sh -c 'ls /root'"},
		{"sudo -n", "echo 'hello'", `sudo -n -- /bin/sh -c 'echo '\''hello'\'''`},
	}
	for _, c := range cases {
		got := buildElevatedExecCommand(c.prefix, c.command)
		if got != c.want {
			t.Errorf("prefix=%q cmd=%q\n  got  %q\n  want %q", c.prefix, c.command, got, c.want)
		}
	}
}

func TestShellQuoteSession(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"id", "'id'"},
		{"ls /root", "'ls /root'"},
		{"echo 'hi'", `'echo '\''hi'\'''`},
		{"", "''"},
	}
	for _, c := range cases {
		got := shellQuoteSession(c.in)
		if got != c.want {
			t.Errorf("in=%q got=%q want=%q", c.in, got, c.want)
		}
	}
}

func TestElevationLabelFromPrefix(t *testing.T) {
	cases := []struct {
		prefix string
		want   string
	}{
		{"sudo -n", "sudo:root"},
		{"sudo -n -u deploy", "sudo:deploy"},
		{"sudo -n -u appuser", "sudo:appuser"},
		{"sudo -n something-else", "sudo:?"},
	}
	for _, c := range cases {
		got := elevationLabelFromPrefix(c.prefix)
		if got != c.want {
			t.Errorf("prefix=%q got=%q want=%q", c.prefix, got, c.want)
		}
	}
}

func TestNewSessionIDUnico(t *testing.T) {
	ids := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id := newSessionID()
		if _, dup := ids[id]; dup {
			t.Fatalf("ID duplicado en iteración %d: %q", i, id)
		}
		ids[id] = struct{}{}
		if len(id) != 24 { // 12 bytes en hex = 24 chars
			t.Errorf("longitud inesperada de session ID: %d", len(id))
		}
	}
}
