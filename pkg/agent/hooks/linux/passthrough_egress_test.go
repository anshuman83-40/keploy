//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"go.keploy.io/server/v3/config"
	"go.keploy.io/server/v3/pkg/agent"
	"go.keploy.io/server/v3/pkg/agent/hooks/structs"
	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// A replay names each port the kernel leaves alone as real egress when the
// client registers, with the knob that put it there; a recording does not,
// and a rule that names a host is the proxy's, not the kernel's.
func TestAReplayNamesTheKernelsPassThroughPortsAsRealEgress(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: uint32(binary.Size(structs.ClientInfo{})), MaxEntries: 1})
	if err != nil {
		t.Skipf("no kernel map to register in (needs root): %v", err)
	}
	defer func() { _ = m.Close() }()
	rules := []models.BypassRule{{Port: 7002}, {Host: "api.example.com", Port: 443}}
	for _, mode := range []models.Mode{models.MODE_TEST, models.MODE_RECORD} {
		core, logs := observer.New(zapcore.InfoLevel)
		h := &Hooks{logger: zap.New(core), clientRegistrationMap: m}
		var opts config.Agent
		opts.Mode = mode
		if err := h.RegisterClient(context.Background(), opts, rules); err != nil {
			t.Fatal(err)
		}
		var got structs.ClientInfo
		if err := m.Lookup(uint64(0), &got); err != nil {
			t.Fatal(err)
		}
		if got.PassThroughPorts[0] != 7002 || got.PassThroughPorts[1] != -1 {
			t.Fatalf("%s: the kernel got pass-through ports %v, want [7002 -1 ...]", mode, got.PassThroughPorts)
		}
		var lines []observer.LoggedEntry
		for _, e := range logs.All() {
			if strings.HasPrefix(e.Message, agent.RealEgressPrefix) {
				lines = append(lines, e)
			}
		}
		if mode == models.MODE_RECORD {
			if len(lines) != 0 {
				t.Fatalf("a recording named real egress: %v", lines)
			}
			continue
		}
		if len(lines) != 1 || !strings.HasPrefix(lines[0].Message, agent.RealEgressPrefix+"bypassRules naming only a port: any host") {
			t.Fatalf("a replay logged %v, want one line naming the port-only bypass rule", lines)
		}
		if ports, ok := lines[0].ContextMap()["ports"].([]interface{}); !ok || len(ports) != 1 || ports[0] != uint(7002) {
			t.Fatalf("the line names ports %#v, want [7002]", lines[0].ContextMap()["ports"])
		}
	}
}
