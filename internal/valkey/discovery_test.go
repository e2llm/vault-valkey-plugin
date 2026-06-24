package valkey

import (
	"context"
	"testing"
)

func TestDiscoverTopology_Standalone(t *testing.T) {
	c := &Config{Host: "vk.example", Port: 6379}
	topo, err := c.discoverTopology(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if topo.Master != "vk.example:6379" {
		t.Errorf("master = %q, want vk.example:6379", topo.Master)
	}
	if len(topo.Nodes) != 1 || topo.Nodes[0] != "vk.example:6379" {
		t.Errorf("nodes = %v, want [vk.example:6379]", topo.Nodes)
	}
}

func TestTopologyString(t *testing.T) {
	topo := &Topology{Master: "a:6379", Nodes: []string{"a:6379", "b:6379"}}
	if got := topo.String(); got != "master=a:6379 nodes=[a:6379 b:6379]" {
		t.Errorf("String() = %q", got)
	}
}
