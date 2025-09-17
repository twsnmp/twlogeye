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
- Windowsイベントログ (Windows環境のみ)

です。

システムの構成は

![](images/twlogeye.png)

です。

ログやレポートの保存にGo言語製の高速Key/Value Store Badgerを
を使用しているため毎秒数万件のログを数TB単位で保存できます。

## Install

Linux/Mac OSの環境では、シェルスクリプトでインストールすることができます。

```terminal
$curl -sS https://lhx98.linkclub.jp/twise.co.jp/download/install_twlogeye.sh | sh
```

Linux/Mac OSではHomebrewでもインストールできます。

```terminal
$brew install twsnmp/tap/twlogeye
```

Linux版のパッケージもリリースに用意してあります。
https://github.com/twsnmp/twlogeye/releases


Winddowsは、リリースのzipファイルをダウンロードするかscoopでインストールできます。


```terminal
>scoop bucket add twsnmp https://github.com/twsnmp/scoop-bucket
>scoop install twlogeye
```

## 基本的な使い方

- ログを保存するディレクトリとSgimaルールを保存するディレクトリを作成
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
$twlogeye help
AI-Native log server to monitor threats in logs with sigma rules
Supported logs are
- syslog
- SNMP trap
- NetFlow/IPFIX
- Windows event log
You can find sigma rule here.
https://github.com/SigmaHQ/sigma

Support MCP server and webhook notify for AI

Usage:
  twlogeye [command]

Available Commands:
  clear       Clear DB of twlogeye
  completion  Generate the autocompletion script for the specified shell
  dashboard   Display twlogeye dashboard
  gencert     Generate TLS private key and cert
  help        Help about any command
  log         Search log
  notify      Search notify
  reload      Reload rules
  report      Get report
  sigma       Check sigma rules (list|stat|logsrc|field|check|test)
  start       Start twlogeye
  stop        Stop twlogeye
  version     Show twlogeye version
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

### ログサーバー
#### start コマンド

サーバーを起動するコマンドです。

```terminal
$twlogeye help start

Start twlogeye

Usage:
  twlogeye start [flags]

Flags:
      --anomalyNotifyDelay int         Grace period for sending notifications when detecting anomalies (default 24)
      --anomalyReportThreshold float   anomaly report threshold
      --anomayUseTime                  Include weekends and hours in the vector data for anomaly detection
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
      --reportInterval int             report interval (minute) (default 5)
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
  twlogeye report <report type> [<anomaly type>] [flags]

Flags:
      --end string     end date and time
  -h, --help           help for report
      --noList         report summary only
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

### dashboard コマンド

ダッシュボードを表示するコマンドです。

![](images/dashboard.png)

```terminal
$twlogeye help dashboard
Display twlogeye dashboard.
<panel type> is
        monitor | anomaly
  syslog.count | syslog.pattern | syslog.error
  trap.count | trap.type
        netflow.count | netflow.ip.packtet | netflow.ip.byte | netflow.mac.packet | netflow.mac.byte
        netflow.flow.packet | netflow.flow.byte | netflow.fumble | netflow.prot
        winevent.count | winevent.pattern | winevent.error

Usage:
  twlogeye dashboard <panel type>... [flags]

Flags:
  -h, --help          help for dashboard
      --history int   Keep report history (default 100)

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
  - `type` (string): レポートの種別 (`syslog`, `trap`, `netflow`, `winevent`, `monitor` のいずれか)。`winevent` は Windowsイベントログを指します。

### `get_anomaly_report`

TwLogEyeから異常検知のレポートを取得します。

- **パラメータ:**
  - `start` (string): レポートの開始日時 (例: `2025/08/30 11:00:00`)。指定しない場合は `1970/01/01 00:00:00` になります。
  - `end` (string): レポートの終了日時 (例: `2025/08/30 11:00:00`)。指定しない場合は現在時刻になります。
  - `type` (string): レポートの種別 (`syslog`, `trap`, `netflow`, `winevent`, `monitor` のいずれか)。`winevent` は Windowsイベントログを指します。

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


`ConfigEnt`構造体の設定ファイルについて、日本語で各項目を説明します。

---

## 設定ファイル項目一覧

### データベースとログのパス
* **`dbPath`**: データベースファイルのパスを指定します。
* **`logPath`**: ログファイルのパスを指定します。

### 受信ポート設定
* **`syslogUDPPort`**: Syslog (UDP) の受信ポート番号。
* **`syslogTCPPort`**: Syslog (TCP) の受信ポート番号。
* **`netFlowPort`**: NetFlow の受信ポート番号。
* **`snmpTrapPort`**: SNMPトラップ の受信ポート番号。

### Windowsイベントログ設定
* **`winEventLogChannel`**: 監視するWindowsイベントログのチャンネル名（例: "System"、"Security"）。
* **`winEventLogCheckInterval`**: イベントログのチェック間隔を秒単位で指定します。
* **`winEventLogCheckStart`**: イベントログの監視を開始する位置を秒単位で指定します。
* **`winRemote`**: Windowsログを取得するリモートホスト名またはIPアドレス。
* **`winUser`**: リモートホストに接続するためのユーザー名。
* **`winPassword`**: リモートホストに接続するためのパスワード。
* **`winAuth`**: 認証方式を指定します。
* **`winLogSJIS`**: WindowsログがShift_JIS形式の場合に`true`を設定します。

### 転送先設定
* **`syslogDst`**: Syslogの転送先ホストのリスト。
* **`trapDst`**: SNMPトラップの転送先ホストのリスト。
* **`webhookDst`**: Webhookの転送先URLのリスト。
* **`trapCommunity`**: SNMPトラップで使用するコミュニティ名。

### データ保持期間設定
* **`logRetention`**: ログの保持期間を時間単位で指定します。
* **`notifyRetention`**: 通知データの保持期間を日単位で指定します。
* **`reportRetention`**: レポートの保持期間を日単位で指定します。

### レポート設定
* **`reportInterval`**: レポートを生成する間隔を`日,時間,分`の形式で指定します。
* **`reportTopN`**: レポートで表示する上位N件の数を指定します。

### 異常検知レポート設定
* **`anomalyReportThreshold`**: 異常検知の閾値を浮動小数点数で指定します。
* **`anomalyUseTimeData`**: 異常検知に曜日や時間帯のデータを使用するかどうかを`true`または`false`で指定します。
* **`anomalyNotifyDelay`**: 異常検知時に通知を送信するまでの猶予期間を時間単位で指定します。

### ログ解析 (GROK)
* **`grokPat`**: GROKパターンを定義するファイルのパスのリスト。
* **`grokDef`**: GROK定義ファイル（例: `grok-patterns`）のパス。

### ログ解析 (Named capture)
* **`namedCaptures`**: ログから特定の情報を抽出するための名前付きキャプチャ設定。

### ログ解析 (Key/Value)
* **`keyValParse`**: ログをKey/Value形式で解析するかどうかを`true`または`false`で指定します。

### Sigmaルール設定
* **`sigmaRules`**: Sigmaルールファイルのパス。
* **`sigmaConfigs`**: Sigma設定ファイルのパス。
* **`sigmaSkipError`**: Sigmaルールの処理中にエラーが発生した場合に、そのルールをスキップするかどうかを`true`または`false`で指定します。

### SNMP MIB設定
* **`mibPath`**: SNMP MIBファイルのパス。

### MCP (Microsoft Cloud) 設定
* **`mcpEndpoint`**: MCPのエンドポイントURL。
* **`mcpFrom`**: MCPからの送信元アドレス。
* **`mcpToken`**: MCPに接続するためのトークン。

### デバッグ
* **`debug`**: デバッグモードを有効にするかどうかを`true`または`false`で指定します。



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
