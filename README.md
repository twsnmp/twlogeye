# twlogeye
Eye-like log server to monitor threats in logs

Import sigma rules.

https://github.com/SigmaHQ/sigma


[日本語のREADME](README-ja.md)

## Install

It is recommended to install the Linux/Mac OS with a shell script.

```terminal
$curl -sS https://lhx98.linkclub.jp/twise.co.jp/download/install_twlogeye.sh | sh
```

Linux/Mac OS can be installed on Homebrew.

```terminal
$brew install twsnmp/tap/twlogeye
```

Winddows downloads zip files from the release or scoop
Install in.

```terminal
>scoop bucket add twsnmp https://github.com/twsnmp/scoop-bucket
>scoop install twlogeye
```

## Basic usage

- Create log and sigma rule directory.
- Create config file.
- Copy or create sigma rules to sigma rule directory
- Start server.

```
~$mkdir logs
~$mkdir sigma
~$code twlogeye.yaml
~$cp <sigma rules> sigma
~$twlogeye start
```

## Command explanation

You can check the commands that support the Help command.

```terminal
Eye-like log server to monitor threats in logs with sigma rules
Supported logs are
- syslog
- SNMP trap
- NetFlow/IPFIX
- Windows Event Log
You can find sigma rule here.
https://github.com/SigmaHQ/sigma

Usage:
  twlogeye [command]

Available Commands:
  clear       Clear DB of twlogeye
  completion  Generate the autocompletion script for the specified shell
  gencert     Generate TLS private key and cert
  help        Help about any command
  log         Search log
  notify      Search notify
  reload      Reload rules
  report      Get report
  sigma       Check sigma rules (list|stat|logsrc|field|check|test)
  start       Start twlogeye
  stop        Stop twlogeye
  watch       Watch notify

Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
  -h, --help                help for twlogeye
      --serverCert string   API server cert
      --serverKey string    API server private key

Use "twlogeye [command] --help" for more information about a command.
```

### Server
#### start command

```terminal
$twlogeye help start

Start twlogeye

Usage:
  twlogeye start [flags]

Flags:
      --anomalyReportThreshold float   anomaly report threshold
  -d, --dbPath string                  DB Path default: memory
      --debug                          debug mode
      --grokDef string                 GROK define file
      --grokPat string                 GROK patterns
  -h, --help                           help for start
      --keyValParse                    Splunk Key value parse
  -l, --logPath string                 Log DB Path default: memory old option
      --logRetention int               log retention(hours) (default 48)
      --mcpEndpoint string             MCP server endpoint
      --mcpFrom string                 MCP server from ip address list
      --mcpToekn string                MCP server token
      --mibPath string                 SNMP Ext MIB Path
      --namedCaptures string           Named capture defs path
      --netflowPort int                netflow port 0=disable
      --notifyRetention int            notify retention(days) (default 7)
      --reportInterval string          report interval (day,hour,minute) (default "hour")
      --reportRetention int            report retention(days) (default 7)
      --reportTopN int                 report top n (default 10)
      --sigmaConfigs string            SIGMA config path
      --sigmaRules string              SIGMA rule path
      --sigmaSkipError                 Skip sigma rule error
      --sjis                           Windows eventlog SHIT-JIS mode
      --syslogDst string               syslog dst
      --syslogTCPPort int              syslog TCP port 0=disable
      --syslogUDPPort int              syslog UDP port 0=disable
      --trapCommunity string           SNMP TRAP Community
      --trapDst string                 SNMP TRAP dst
      --trapPort int                   SNMP TRAP recive port 0=disable
      --webhookDst string              Webhook dst URL
      --winAuth string                 Windows eventlog auth
      --winEventLogChannel string      Windows eventlog channel
  -i, --winEventLogCheckInterval int   Windows evnetlog check interval
  -s, --winEventLogCheckStart int      Windows evnetlog check start time (hours)
      --winPassword string             Windows eventlog password
      --winUser string                 Windows eventlog user

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key
```


### Client
#### log command

```terminal
$twlogeye help log

Search log via api

Usage:
  twlogeye log [flags]

Flags:
      --end string       end date and time
  -h, --help             help for log
      --logtype string   log type  (default "syslog")
      --search string    search text
      --start string     start date and time

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key
```

#### notify command
```terminal
$twlogeye help notify
Serach notify via api

Usage:
  twlogeye notify [flags]

Flags:
      --end string     notify level
  -h, --help           help for notify
      --level string   notify level
      --start string   start date and time

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key

```

#### watch command
```
$twlogeye help watch 
Watch notify via api

Usage:
  twlogeye watch [flags]

Flags:
  -h, --help   help for watch

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key
```

#### report command

get report

```
$twlogeye help report
Get report via api

Usage:
  twlogeye report [flags]

Flags:
      --end string          end date and time
  -h, --help                help for report
      --noList              report summary only
      --reportType string   report type
      --start string        start date and time

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key
```


#### stop command
```
$twlogeye help stop
Stop twlogeye via api

Usage:
  twlogeye stop [flags]

Flags:
  -h, --help   help for stop

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key
```

#### reload command

```
$twlogeye help reload
Reload rules via api

Usage:
  twlogeye reload [flags]

Flags:
  -h, --help   help for reload

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert

```

#### clear command

Clear logs ,notify report on DB. 

```
$twlogeye help clear
Clear DB of twlogeye via api type is "logs","notify","report"

Usage:
  twlogeye clear <type> <subtype> [flags]

Flags:
  -h, --help   help for clear

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key
```


### Util
#### gencert command

```
＄twlogeye  help gencert
Generate TLS private key and cert for gRPC server/client

Usage:
  twlogeye gencert [flags]

Flags:
      --cn string   CN for client cert (default "twsnmp")
  -h, --help        help for gencert

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key

```

Generate client cert and key.
```terminal
$twlogeye gencert --clientCert c.crt --clientKey k.key
```
Generate sercer cert and key.
```terminal
$twlogeye gencert --serverCert s.crt --serverKey s.key
```

#### sigma command

```terminal
Check sigma rules (list|stat|logsrc|field|check|test)
	list: list rules
	stat: stat rules
	logsrc: list log srourcese
	field: list fields
	check: check rule
	test: test rule args

Usage:
  twlogeye sigma [flags]

Flags:
  -h, --help                help for sigma
      --sigmaRules string   SIGMA rule path

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key
```

## MCP Server Tool Specifications

This document describes the tools and their parameters for the MCP server defined in `mcp.go`.

### `search_log`

Searches for logs from TwLogEye.

- **Parameters:**
  - `start` (string): The date and time to start the search (e.g., `2025/08/30 11:00:00`). If not specified, it defaults to `1970/01/01 00:00:00`.
  - `end` (string): The date and time to end the search (e.g., `2025/08/30 11:00:00`). If not specified, it defaults to the current time.
  - `type` (string): The type of log (one of `syslog`, `trap`, `netflow`, `winevent`).
  - `filter` (string): A regular expression to filter logs.

### `search_notify`

Searches for notifications from TwLogEye.

- **Parameters:**
  - `start` (string): The date and time to start the search (e.g., `2025/08/30 11:00:00`). If not specified, it defaults to `1970/01/01 00:00:00`.
  - `end` (string): The date and time to end the search (e.g., `2025/08/30 11:00:00`). If not specified, it defaults to the current time.
  - `level` (string): A regular expression to filter notification levels (e.g., `high|critical`). If not specified, no filtering is applied. Level names include `info`, `low`, `medium`, `high`, `critical`, etc.

### `get_report`

Retrieves a report from TwLogEye.

- **Parameters:**
  - `start` (string): The start date and time for the report (e.g., `2025/08/30 11:00:00`). If not specified, it defaults to `1970/01/01 00:00:00`.
  - `end` (string): The end date and time for the report (e.g., `2025/08/30 11:00:00`). If not specified, it defaults to the current time.
  - `type` (string): The type of report (one of `syslog`, `trap`, `netflow`, `winevent`, `anomaly`,`monitor`). `winevent` refers to Windows Event Logs.

### `get_sigma_evaluator_list`

Retrieves a list of Sigma rule evaluators from TwLogEye.

- **Parameters:** None

### `get_sigma_rule_id_list`

Retrieves a list of Sigma rule IDs from TwLogEye.

- **Parameters:** None

### `get_sigma_rule`

Retrieves a Sigma rule with the specified ID from TwLogEye.

- **Parameters:**
  - `id` (string): The ID of the Sigma rule to retrieve.

### `add_sigma_rule`

Adds a new Sigma rule to TwLogEye.

- **Parameters:**
  - `rule` (string): The Sigma rule string in YAML format.

### `delete_sigma_rule`

Deletes a Sigma rule with the specified ID from TwLogEye.

- **Parameters:**
  - `id` (string): The ID of the Sigma rule to delete.

### `reload_sigma_rule`

Reloads the Sigma rules loaded in TwLogEye.

- **Parameters:** None



## Setting file

Use the file specified in --config or the current directory ./twlogeye.yaml as the configuration file.
YAML format.It corresponds to the following keys.

| Key | Descr |
| --- | --- |
|logPath| Log DB path|
|syslogUDPPort| syslog UDP port|
|syslogTCPPort| syslog TCP port|
|netflowPort| NetFlow port|
|snmpTrapPort|SNMP Trap port|
|winEventLogChannel|Windows Event Log Channel|
|winEventLogCheckInterval|Windows check interval (sec)
|winEventLogCheckStart|Windows Event Log check start time(hour)|
|winRemote|Windows Event log remote host|
|winUser|Windows Event log user|
|winPassword|Windows Event log password|
|winAuth|Windows Event log auth mode| 
|winSJIS|Windows Event log is SHIF-JIS|
|syslogDst| syslog notify dst|
|trapDst|SNMP TRAP notify dst|
|trapCommunity|SNMP TRAP Community|
|logRetention|Log retention(hour)|
|notifyRetention|Notify retention(days)|
|grockPat|GROK pattern|
|grokDef|GROK Def file path|
|namedCaptures|Name Captures def file path|
|keyValParse|Splunk syle key value parser|
|sigmaRules|sigma rules path|
|sigmaConfigs|sigma config path|
|sigmaSkipError|Skip sigma rule and config error|
|mibPath|SNMP MIB path|
|debug|Debug mod sigma rule match|


## environmental variables

The following environment variables are available.

| Key | Descr |
| --- | ---- |
| TWLOGEYE_APIPORT | API port number |
| TWLOGEYE_APISERVER | API server ip or host name |
| TWLOGEYE_SERVERCERT | Server cert file path |
| TWLOGEYE_SERVERKEY | Server private key path |
| TWLOGEYE_CLIENTCERT | Client cert file path |
| TWLOGEYE_CLIENTKEY | Client private key path |

## Build

Use go-task for builds.
https://taskfile.dev/

```terminal
$task
```


## Copyright

see [LICENSE](./LICENSE)

```
Copyright 2025 Masayuki Yamai
```
