package valkey

import (
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/helper/template"
)

// defaultUsernameTemplate produces names like
//
//	v_<display8>_<role8>_<random20>_<unixtime>
//
// lowercased and capped at 64 chars. The display/role prefixes make ACL
// key-pattern-by-username schemes and audit correlation practical.
const defaultUsernameTemplate = `{{ printf "v_%s_%s_%s_%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 64 | lowercase }}`

func generateUsername(meta dbplugin.UsernameMetadata, tmpl string) (string, error) {
	if tmpl == "" {
		tmpl = defaultUsernameTemplate
	}
	t, err := template.NewTemplate(template.Template(tmpl))
	if err != nil {
		return "", err
	}
	return t.Generate(meta)
}
