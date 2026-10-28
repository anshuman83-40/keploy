package agent

import (
	"slices"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// The kernel gets the sources' ports in order, at most its limit, and each
// source is named with only the ports that made the list: a port past the
// limit is redirected, so naming it as opened would be false.
func TestKernelPassThroughNamesOnlyThePortsTheKernelGets(t *testing.T) {
	sources := []PassThroughSource{
		{Knob: "rules", Ports: []uint{7002, 7003}},
		{Knob: "empty"},
		{Knob: "extra", Ports: []uint{8001, 8002}},
		{Knob: "agent", Ports: []uint{16789}},
	}
	ports, kept := KernelPassThrough(sources, 3)
	if !slices.Equal(ports, []uint{7002, 7003, 8001}) {
		t.Fatalf("ports %v, want [7002 7003 8001]", ports)
	}
	want := []PassThroughSource{{Knob: "rules", Ports: []uint{7002, 7003}}, {Knob: "extra", Ports: []uint{8001}}}
	if !slices.EqualFunc(kept, want, func(a, b PassThroughSource) bool { return a.Knob == b.Knob && slices.Equal(a.Ports, b.Ports) }) {
		t.Fatalf("kept %v, want %v", kept, want)
	}
	if _, kept := KernelPassThrough([]PassThroughSource{{Knob: "rules"}}, 10); len(kept) != 0 {
		t.Fatalf("no port named %v", kept)
	}
}

// Every knob's line has the one form a search finds.
func TestLogRealEgressHasOneForm(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	LogRealEgress(zap.New(core), "mock.real", "these destinations", zap.Int("n", 1))
	all := logs.All()
	if len(all) != 1 || all[0].Message != RealEgressPrefix+"mock.real: these destinations" || all[0].Level != zapcore.InfoLevel {
		t.Fatalf("logged %+v", all)
	}
}
