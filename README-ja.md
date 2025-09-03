# twlogeye

twlogeyeはAIネイティブなログサーバーです。

SIGMAルール

https://github.com/SigmaHQ/sigma

を直接読み込み脅威の検知をすることができます。
MCPサーバーに対応しておりAIがログ分析することを助けます。
WebhookによりAI対応の自動化ツールに通知することができます。
機械学習によりログから異常を検知できます。

対応しているログは

- syslog
- SNMP Trap
- Netflow
- Windows Event log (Windows環境のみ)


## Install

Linux/Mac OSの環境では、シェルスクリプトでインストールすることができます。

```terminal
$curl -sS https://lhx98.linkclub.jp/twise.co.jp/download/install_twlogeye.sh | sh
```

Linux/Mac OSではHomebrewでもインストールできます。

```terminal
$brew install twsnmp/tap/twlogeye
```

Winddowsは、リリースのzipファイルをダウンロードするかscoopでインストールできます。


```terminal
>scoop bucket add twsnmp https://github.com/twsnmp/scoop-bucket
>scoop install twlogeye
```

## 基本的な使い方

- ログを保存するディレクトリとSgmaルールを保存するディレクトリを作成
- 設定ファイルを作成
- Sigmaルールをコピーまたは、作成
- サーバーを開始

```
~$mkdir logs
~$mkdir sigma
~$code twlogeye.yaml
~$cp <sigma rules> sigma
~$twlogeye start
```

## コマンドの説明

helpコマンドで確認できます。

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

### ロウサーバー
#### start コマンド

サーバーを起動するコマンドです。

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


### クライアント
#### log コマンド

サーバーに保存されたログを検索するためのコマンドです。

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

#### notify コマンド

サーバーに保存された通知を検索するコマンドです。

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

#### watch コマンド

サーバーで発生する通知をリアルタイムで監視するコマンドです。


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

#### report コマンド

レポートを表示するコマンドです。

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


#### stop コマンド

サーバーを停止するコマンドです。

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

#### reload コマンド

サーバーにSigmaルールの再読み込みを指示するコマンドです。

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

#### clear コマンド

データベース上のログ、通知、レポートをクリアするコマンドです。

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
#### gencert コマンド

サーバーとクライアントのgRPC通信を暗号化するための証明書、秘密鍵を作成するコマンドです。

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

クライアントは
```terminal
$twlogeye gencert --clientCert c.crt --clientKey k.key
```
サーバーは
```terminal
$twlogeye gencert --serverCert s.crt --serverKey s.key
```
で作成します。

#### sigma コマンド

sigmaルールを確認するためのコマンドです。

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

## MCPサーバー ツールの仕様

`mcp.go`で定義されているMCPサーバーのツールとそのパラメータについて説明します。

### `search_log`

TwLogEyeからログを検索します。

- **パラメータ:**
  - `start` (string): 検索を開始する日時 (例: `2025/08/30 11:00:00`)。指定しない場合は `1970/01/01 00:00:00` になります。
  - `end` (string): 検索を終了する日時 (例: `2025/08/30 11:00:00`)。指定しない場合は現在時刻になります。
  - `type` (string): ログの種別 (`syslog`, `trap`, `netflow`, `winevent` のいずれか)。
  - `filter` (string): ログをフィルタリングするための正規表現。

### `search_notify`

TwLogEyeから通知を検索します。

- **パラメータ:**
  - `start` (string): 検索を開始する日時 (例: `2025/08/30 11:00:00`)。指定しない場合は `1970/01/01 00:00:00` になります。
  - `end` (string): 検索を終了する日時 (例: `2025/08/30 11:00:00`)。指定しない場合は現在時刻になります。
  - `level` (string): 通知レベルをフィルタリングするための正規表現 (例: `high|critical`)。指定しない場合はフィルタリングされません。レベル名には `info`, `low`, `medium`, `high`, `critical` などがあります。

### `get_report`

TwLogEyeからレポートを取得します。

- **パラメータ:**
  - `start` (string): レポートの開始日時 (例: `2025/08/30 11:00:00`)。指定しない場合は `1970/01/01 00:00:00` になります。
  - `end` (string): レポートの終了日時 (例: `2025/08/30 11:00:00`)。指定しない場合は現在時刻になります。
  - `type` (string): レポートの種別 (`syslog`, `trap`, `netflow`, `winevent`, `anomaly`,`monitor` のいずれか)。`winevent` は Windowsイベントログを指します。

### `get_sigma_evaluator_list`

TwLogEyeからSigmaルール評価器のリストを取得します。

- **パラメータ:** なし

## `get_sigma_rule_id_list`

TwLogEyeからSigmaルールのIDリストを取得します。

- **パラメータ:** なし

### `get_sigma_rule`

TwLogEyeから指定したIDのSigmaルールを取得します。

- **パラメータ:**
  - `id` (string): 取得するSigmaルールのID。

### `add_sigma_rule`

TwLogEyeに新しいSigmaルールを追加します。

- **パラメータ:**
  - `rule` (string): YAML形式のSigmaルール文字列。

### `delete_sigma_rule`

TwLogEyeから指定したIDのSigmaルールを削除します。

- **パラメータ:**
  - `id` (string): 削除するSigmaルールのID。

### `reload_sigma_rule`

TwLogEyeにロードされているSigmaルールを再読み込みします。

- **パラメータ:** なし


## 設定ファイル

--config パラメータで指定するか、カレントディレクトリの ./twlogeye.yamlを設定ファイルとして使用します。YAML形式です。

| キー | 説明 |
| --- | --- |
|logPath| Log DBのパス|
|syslogUDPPort| syslog UDP 受信ポート|
|syslogTCPPort| syslog TCP 受信ポート|
|netflowPort| NetFlow 受信ポート|
|snmpTrapPort|SNMP Trap 受信ポート|
|winEventLogChannel|Windowsイベントログの監視チャネル|
|winEventLogCheckInterval|Windowsイベントログの監視周期(秒単位)|
|winEventLogCheckStart|Windowsイベントログの監視開始時間|
|winRemote|Windowsイベントログを監視するリモートホスト|
|winUser|Windowsイベントログを監視するリモートホストのユーザー|
|winPassword|Windowsイベントログを監視するリモートホストのユーザーのパスワード|
|winAuth|Windowsイベントログを監視するリモートホストへの認証方式| 
|winSJIS|Windowsイベントログの文字コードがSHIF-JIS|
|syslogDst| syslog通知の宛先|
|trapDst|SNMP TRAP通知の宛先|
|trapCommunity|SNMP TRAP通知のCommunity名|
|logRetention|ログの保存時間|
|notifyRetention|通知の保存日数|
|grockPat|GROKパターン定義|
|grokDef|GROK定義ファイルのパス|
|namedCaptures|正規表現の定義ファイルパス|
|keyValParse|Splunkのようなキーバリューの取得を行う|
|sigmaRules|sigmaルールのパス|
|sigmaConfigs|sigma設定のパス|
|sigmaSkipError|Sigmaルール、設定の読み込みエラーを無視する|
|mibPath|SNMP MIBのパス|
|debug|デバックモード|


## 環境変数

The following environment variables are available.

| Key | Descr |
| --- | ---- |
| TWLOGEYE_APIPORT | API ポート番号 |
| TWLOGEYE_APISERVER | API サーバーアドレス|
| TWLOGEYE_SERVERCERT | サーバー証明書のパス |
| TWLOGEYE_SERVERKEY | サーバーの秘密鍵のパス |
| TWLOGEYE_CLIENTCERT | クライアント証明書のパス |
| TWLOGEYE_CLIENTKEY | クライアントの秘密鍵のパス |
| TWLOGEYE_CACERT | CA証明書のパス|

## ビルド方法

ビルドには

https://taskfile.dev/

を利用します。

```terminal
$task
```


## Copyright

[LICENSE](./LICENSE)を参照してください。

```
Copyright 2025 Masayuki Yamai
```
