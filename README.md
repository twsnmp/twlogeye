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
Eye-like log server to monitor threats in logs with signa rules
Supported logs are
- syslog
- NetFlow/IPFIX
- Windows Event Log
You can find sigma rule here.
https://github.com/SigmaHQ/sigma

Usage:
  twlogeye [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  gencert     Generate TLS private key and cert
  help        Help about any command
  log         Search log
  notify      Serach notify
  reload      Reload rules
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
      --debug                          debug mode
      --grokDef string                 GROK define file
      --grokPat string                 GROK patterns
  -h, --help                           help for start
      --keyValParse                    Splunk Key value parse
  -l, --logPath string                 Log DB Path default: memory
      --logRetention int               log retention(hours) (default 48)
      --mibPath string                 SNMP Ext MIB Path
      --namedCap string                Named capture defs path
      --netflowPort int                netflow port 0=disable
      --notifyRetention int            notify retention(days) (default 30)
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
|namedCaps|Name Captures def file path|
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

## Copyright

see [LICENSE](./LICENSE)

```
Copyright 2025 Masayuki Yamai
```
