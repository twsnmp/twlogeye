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

## Docker

Docker版の起動方法は

```
$mkdir ./twlogeye
$vi ./twlogeye/config.yaml
$docker run --rm -v ./twlogeye:/datastore \
-p 2055:2055/udp -p 514:514/udp -p 162:162/udp -p 1883:1883 \
-e TZ=Asia/Tokyo twsnmp/twlogeye
```

config.yamlを編集してください。

ダッシュボードの表示は

```
$docker exec -it <コンテナID> /twlogeye dashboard \
monitor anomaly netflow.count mqtt.count
```

![Dashboard](https://assets.st-note.com/img/1762982295-vQB5Ki9Pq3TRGw7oWSfsc0Ly.png?width=1200)



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
- OptenTelemetry
- MQTT
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
  otel        Get OpenTelemetry info
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
      --geoIPDB string                 Geo IP Database Path
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
      --mqttCert string                MQTT server certficate
      --mqttFrom string                MQTT clinet IPs
      --mqttKey string                 MQTT server private key
      --mqttTCPPort int                MQTT TCP Port
      --mqttUsers string               MQTT user and password
      --mqttWSPort int                 MQTT Websock Port
      --namedCaptures string           Named capture defs path
      --netflowPort int                netflow port 0=disable
      --notifyRetention int            notify retention(days) (default 7)
      --otelCA string                  OpenTelemetry CA certficate
      --otelCert string                OpenTelemetry server certficate
      --otelFrom string                OpenTelemetry clinet IPs
      --otelHTTPPort int               OpenTelemetry HTTP Port
      --otelKey string                 OpenTelemetry server private key
      --otelRetention int              log retention(hours) (default 48)
      --otelgRPCPort int               OpenTelemetry gRPC Port
      --reportInterval int             report interval (minute) (default 5)
      --reportRetention int            report retention(days) (default 7)
      --reportTopN int                 report top n (default 10)
      --resolveHostName                Resolve Host Name
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
  netflow.host | netflow.loc | netflow.country
  winevent.count | winevent.pattern | winevent.error
  otel.count | otel.pattern | otel.error | otel.metric.<id>
  mqtt.count | mqtt.type

Usage:
  twlogeye dashboard <panel type>... [flags]

Flags:
  -h, --help          help for dashboard
      --history int   Keep report history (default 100)
      --topn int      Number of top n lines. (default 5)

Global Flags:
  -p, --apiPort int         API Server port (default 8081)
      --apiServer string    server IP or host name (default "localhost")
      --caCert string       API CA cert
      --clientCert string   API client cert
      --clientKey string    API client private key
      --config string       config file (default is ./twlogeye.yaml)
      --serverCert string   API server cert
      --serverKey string    API server private key```
```

#### otel コマンド

This is a command to obtain OpenTelemetry metrics and traces.

```
$twlogeye help otel
Get OpenTelemetry info via api

Usage:
  twlogeye otel <metric|trace> <list|id> [flags]

Flags:
  -h, --help   help for otel

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
  - `type` (string): ログの種別 (`syslog`, `trap`, `netflow`, `winevent`, `otel`, `mqtt` のいずれか)。
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
  - `type` (string): レポートの種別 (`syslog`, `trap`, `netflow`, `winevent`, `otel`, `mqtt`, `anomaly`, `monitor` のいずれか)。`winevent` は Windowsイベントログを指します。

### `get_anomaly_report`

TwLogEyeから異常検知のレポートを取得します。

- **パラメータ:**
  - `start` (string): レポートの開始日時 (例: `2025/08/30 11:00:00`)。指定しない場合は `1970/01/01 00:00:00` になります。
  - `end` (string): レポートの終了日時 (例: `2025/08/30 11:00:00`)。指定しない場合は現在時刻になります。
  - `type` (string): 異常検知レポートの種別 (`syslog`, `trap`, `netflow`, `winevent`, `otel`, `monitor` のいずれか)。`winevent` は Windowsイベントログを指します。

### `get_last_report`

TwLogEyeから最新のレポートを取得します。

- **パラメータ:**
  - `type` (string): レポートの種別 (`syslog`, `trap`, `netflow`, `winevent`, `otel`, `anomaly`, `monitor` のいずれか)。`winevent` は Windowsイベントログを指します。

### `get_sigma_evaluator_list`

TwLogEyeからSigmaルール評価器のリストを取得します。

- **パラメータ:** なし

### `get_sigma_rule_id_list`

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

--config パラメータで指定するか、カレントディレクトリの `./twlogeye.yaml` を設定ファイルとして使用します。YAML形式です。

### コア設定

* **`dbPath`**: データベースファイルのパスを指定します。

---

### 受信データポート

* **`syslogUDPPort`**: SyslogメッセージをUDPで受信するポート。
* **`syslogTCPPort`**: SyslogメッセージをTCPで受信するポート。
* **`netflowPort`**: NetFlowデータを受信するポート。
* **`snmpTrapPort`**: SNMPトラップメッセージを受信するポート。
* **`otelHTTPPort`**: OpenTelemetryメッセージをHTTP/JSONで受信するポート。
* **`otelgRPCPort`**: OpenTelemetryメッセージをgRPCで受信するポート。
* **`mqttTCPPort`**: MQTTブローカーのTCPポート。
* **`mqttWSPort`**: MQTTブローカーのWebSocketポート。

---

### OpenTelemetry設定

* **`otelRetention`**: OpenTelemetryのログ保持期間を時間単位で指定します。
* **`otelFrom`**: OpenTelemetryの許可されたクライアントIPアドレスのリスト。
* **`otelCert`**: OpenTelemetryサーバーの証明書パス。
* **`otelKey`**: OpenTelemetryサーバーの秘密鍵パス。
* **`otelCA`**: OpenTelemetryのCA証明書パス。

---

### MQTTサーバー設定

* **`mqttUsers`**: MQTTクライアントの `ユーザー名:パスワード` のカンマ区切りリスト。
* **`mqttFrom`**: MQTTの許可されたクライアントIPアドレスのリスト。
* **`mqttCert`**: MQTTサーバーの証明書パス。
* **`mqttKey`**: MQTTサーバーの秘密鍵パス。

---

### Windowsイベントログ収集

* **`winEventLogChannel`**: 監視するWindowsイベントログのチャンネル名（例: "System", "Security"）。
* **`winEventLogCheckInterval`**: イベントログのチェック間隔を秒単位で指定します。
* **`winEventLogCheckStart`**: イベントログの監視を開始する起点（過去からの時間）を時間単位で指定します。
* **`winRemote`**: リモートWindowsマシンのホスト名またはIPアドレス。
* **`winUser`**: リモートマシン認証用のユーザー名。
* **`winPassword`**: 認証用のパスワード。
* **`winAuth`**: 使用する認証方法。
* **`winLogSJIS`**: WindowsログがShift JISエンコーディングである場合に `true` を設定するブール値フラグ。

---

### 転送先設定

* **`syslogDst`**: Syslogメッセージの転送先ホストのリスト。
* **`trapDst`**: SNMPトラップの転送先ホストのリスト。
* **`webhookDst`**: Webhookの転送先URLのリスト。
* **`mqttDst`**: MQTTメッセージの転送先MQTTブローカーのリスト。
* **`trapCommunity`**: トラップに使用されるSNMPコミュニティ文字列。

---

### データ保持期間

* **`logRetention`**: ログの保持期間を時間単位で指定します。
* **`notifyRetention`**: 通知データの保持期間を日単位で指定します。
* **`reportRetention`**: レポートデータの保持期間を日単位で指定します。

---

### レポート設定

* **`reportInterval`**: レポート生成の間隔を分単位で指定します。
* **`reportTopN`**: レポートに含める上位N件の数。

---

### 異常検知

* **`anomalyReportThreshold`**: 異常検知の閾値を表す浮動小数点値。
* **`anomalyUseTimeData`**: 異常検知分析に時間と曜日のデータを含めるかどうかのブール値フラグ。
* **`anomalyNotifyDelay`**: 異常検知時に通知を送信するまでの猶予期間を時間単位で指定します。

---

### ログ解析

* **`grokPat`**: Grokパターンを含むファイルのパスのリスト。
* **`grokDef`**: Grok定義ファイル（例: `grok-patterns`）のパス。
* **`namedCaptures`**: ログから特定の情報を抽出するための名前付きキャプチャグループの設定。
* **`keyValParse`**: キー/値ログ解析を有効または無効にするブール値フラグ。

---

### Sigmaルール

* **`sigmaRules`**: Sigmaルールファイルのパス。
* **`sigmaConfigs`**: Sigma設定ファイルのパス。
* **`sigmaSkipError`**: 処理中にエラーが発生した場合にルールをスキップするかどうかのブール値フラグ。

---

### その他の設定

* **`resolveHostName`**: IPアドレスからホスト名を解決するかどうかのブール値フラグ。
* **`geoIPDB`**: GeoIPデータベースファイルのパス。
* **`mibPath`**: SNMP MIBファイルのパス。
* **`mcpEndpoint`**: Microsoft Cloud Platform (MCP) のエンドポイントURL。
* **`mcpFrom`**: MCPに送信されるメッセージの"From"アドレス。
* **`mcpToken`**: MCPの認証トークン。
* **`debug`**: デバッグモードを有効または無効にするブール値フラグ。



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
