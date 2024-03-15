package as3parsing

import (
	"embed"

	f5_bigip "github.com/f5devcentral/f5-bigip-rest-go/bigip"
)

var (
	properties map[string]Properties
	// slog       *utils.SLOG
	as3Service string
	bigip      *f5_bigip.BIGIP
	//go:embed rest.properties.json
	propFile embed.FS
)
