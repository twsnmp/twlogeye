module github.com/twsnmp/twlogeye

go 1.24

toolchain go1.24.0

require (
	github.com/araddon/dateparse v0.0.0-20210429162001-6b43995a97de
	github.com/bradleyjkemp/sigma-go v0.6.6
	github.com/codegaudi/go-iforest v0.0.1
	github.com/dgraph-io/badger/v4 v4.5.0
	github.com/elastic/go-grok v0.3.1
	github.com/gosnmp/gosnmp v1.38.0
	github.com/labstack/echo/v4 v4.13.4
	github.com/mark3labs/mcp-go v0.38.0
	github.com/montanaflynn/stats v0.7.1
	github.com/sleepinggenius2/gosmi v0.4.4
	github.com/spf13/cobra v1.8.1
	github.com/spf13/viper v1.19.0
	github.com/tehmaze/netflow v0.0.0-20170921210347-852af103667f
	github.com/twsnmp/go-mibdb v0.0.0-20210104220414-91387072cee7
	github.com/twsnmp/twlogeye/api v0.1.1
	golang.org/x/text v0.25.0
	google.golang.org/grpc v1.72.1
	gopkg.in/mcuadros/go-syslog.v2 v2.3.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/BobuSumisu/aho-corasick v1.0.3 // indirect
	github.com/PaesslerAG/gval v1.0.0 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/alecthomas/participle v0.7.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.0.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/invopop/jsonschema v0.13.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.35.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250218202821-56aae31c358a // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
)

replace github.com/twsnmp/twlogeye/api => ./api
