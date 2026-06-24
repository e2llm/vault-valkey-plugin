// Command valkey-database-plugin is a HashiCorp Vault / OpenBao database secrets
// engine plugin (dbplugin v5) that issues dynamic Valkey credentials across a
// Sentinel-managed primary/replica topology.
//
// Because Valkey ACL users are node-local (they are NOT propagated by replication
// nor carried by a replica resync — verified in test/sentinel/spike.sh), the
// plugin provisions, persists, and revokes each dynamic user on every node, and
// re-resolves the current master through Sentinel on every operation.
package main

import (
	"fmt"
	"os"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"

	"github.com/e2llm/vault-valkey-plugin/internal/valkey"
)

// version is injected at build time via -ldflags "-X main.version=vX.Y.Z".
// It defaults to "dev"; there is no version constant maintained in source.
var version = "dev"

func main() {
	for _, a := range os.Args[1:] {
		if a == "-version" || a == "--version" {
			fmt.Println("valkey-database-plugin", version)
			return
		}
	}

	valkey.Version = version
	dbplugin.ServeMultiplex(valkey.New)
}
