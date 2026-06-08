package main

import "testing"

func TestResolveCaller(t *testing.T) {
	forwarders := map[string]struct{}{"control-plane-1": {}}

	cases := []struct {
		name       string
		mtlsCN     string
		onBehalfOf string
		wantCaller string
		wantOK     bool
	}{
		{
			name:       "broker directo sin on_behalf_of usa su CN",
			mtlsCN:     "broker-1",
			onBehalfOf: "",
			wantCaller: "broker-1",
			wantOK:     true,
		},
		{
			name:       "forwarder de confianza actúa en nombre del broker",
			mtlsCN:     "control-plane-1",
			onBehalfOf: "broker-1",
			wantCaller: "broker-1",
			wantOK:     true,
		},
		{
			name:       "broker no-forwarder no puede suplantar (rechazado)",
			mtlsCN:     "broker-1",
			onBehalfOf: "broker-2",
			wantOK:     false,
		},
		{
			name:       "forwarder sin on_behalf_of usa su propio CN",
			mtlsCN:     "control-plane-1",
			onBehalfOf: "",
			wantCaller: "control-plane-1",
			wantOK:     true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			caller, ok := resolveCaller(c.mtlsCN, c.onBehalfOf, forwarders)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, quiero %v", ok, c.wantOK)
			}
			if ok && caller != c.wantCaller {
				t.Errorf("caller = %q, quiero %q", caller, c.wantCaller)
			}
		})
	}
}
