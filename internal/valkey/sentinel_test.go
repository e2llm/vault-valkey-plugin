package valkey

import "testing"

func TestIsDownReplica(t *testing.T) {
	down := []string{"slave,s_down", "slave,o_down", "slave,disconnected", "slave,s_down,disconnected"}
	for _, f := range down {
		if !isDownReplica(f) {
			t.Errorf("flags %q should be considered down", f)
		}
	}
	up := []string{"slave", "master", "slave,online"}
	for _, f := range up {
		if isDownReplica(f) {
			t.Errorf("flags %q should be considered up", f)
		}
	}
}
