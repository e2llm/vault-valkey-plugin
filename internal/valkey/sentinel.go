package valkey

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/redis/go-redis/v9"
)

// discoverTopology resolves the current master and live replicas. In Sentinel
// mode it queries each configured Sentinel until one answers, so a single dead
// Sentinel does not break credential operations. In standalone mode it returns
// the single configured node.
//
// Topology is resolved fresh on every operation: after a failover the master
// moves, and a stale cached topology would point ACL writes at a demoted node.
func (c *Config) discoverTopology(ctx context.Context) (*Topology, error) {
	if len(c.Sentinels) == 0 {
		addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
		return &Topology{Master: addr, Nodes: []string{addr}}, nil
	}

	var errs []string
	for _, s := range c.Sentinels {
		sc, err := c.sentinelClient(s)
		if err != nil {
			return nil, err
		}
		topo, err := c.topologyFromSentinel(ctx, sc)
		_ = sc.Close()
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", s, err))
			continue
		}
		if c.sharedSentinelIdentity() {
			topo.Sentinels = append([]string(nil), c.Sentinels...)
		}
		return topo, nil
	}
	return nil, fmt.Errorf("no Sentinel could resolve master %q: %s", c.SentinelMasterName, strings.Join(errs, "; "))
}

func (c *Config) topologyFromSentinel(ctx context.Context, sc *redis.SentinelClient) (*Topology, error) {
	addr, err := sc.GetMasterAddrByName(ctx, c.SentinelMasterName).Result()
	if err != nil {
		return nil, fmt.Errorf("get-master-addr-by-name: %w", err)
	}
	if len(addr) != 2 {
		return nil, fmt.Errorf("unexpected master address response %v", addr)
	}
	master := net.JoinHostPort(addr[0], addr[1])

	replicas, err := sc.Replicas(ctx, c.SentinelMasterName).Result()
	if err != nil {
		return nil, fmt.Errorf("replicas: %w", err)
	}

	nodes := []string{master}
	seen := map[string]bool{master: true}
	for _, r := range replicas {
		if isDownReplica(r["flags"]) {
			continue
		}
		ip, port := r["ip"], r["port"]
		if ip == "" || port == "" {
			continue
		}
		a := net.JoinHostPort(ip, port)
		if !seen[a] {
			seen[a] = true
			nodes = append(nodes, a)
		}
	}
	return &Topology{Master: master, Nodes: nodes}, nil
}

// isDownReplica reports whether a Sentinel replica "flags" field indicates the
// replica is not currently usable (subjectively/objectively down or disconnected).
func isDownReplica(flags string) bool {
	for _, f := range []string{"s_down", "o_down", "disconnected"} {
		if strings.Contains(flags, f) {
			return true
		}
	}
	return false
}
