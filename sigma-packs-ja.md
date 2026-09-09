# twlogeye 組み込み Sigma ルールパック詳細ガイド

twlogeye には、セキュリティ監視において即効性が高く誤検知の少ない **7つの推奨ルールパック（合計57ルール）** が標準で組み込まれています。
外部からルールファイルをダウンロード・配置することなく、設定ファイル（`twlogeye.yaml`）または起動オプションでパック名を指定するだけですぐに高精度な脅威検知を開始できます。

---

## 目次

1. [ルールパックの概要と使い方](#1-ルールパックの概要と使い方)
2. [ルールパック一覧](#2-ルールパック一覧)
3. [各パックの詳細と収録ルール](#3-各パックの詳細と収録ルール)
   - [windows-essential (Windows標準重要イベント)](#windows-essential)
   - [windows-ad (Active Directory / ドメイン侵害)](#windows-ad)
   - [windows-client (Windows端末・エンドポイント脅威)](#windows-client)
   - [linux-auth (Linux認証・特権昇格)](#linux-auth)
   - [linux-system (Linux永続化・システム改ざん)](#linux-system)
   - [network-threats (ネットワーク機器・FW・VPN)](#network-threats)
   - [web-attacks (Webサーバー・プロキシ攻撃)](#web-attacks)
4. [カスタムルールとの併用と優先度オーバーライド](#4-カスタムルールとの併用と優先度オーバーライド)

---

## 1. ルールパックの概要と使い方

### 設定ファイルでの指定 (`twlogeye.yaml`)
有効にしたいパックを `sigmaPacks` にリスト形式で指定します：

```yaml
sigmaPacks:
  - windows-essential
  - windows-ad
  - windows-client
  - linux-auth
  - linux-system
  - network-threats
  - web-attacks
```

### コマンドライン引数での指定
サーバー起動時に直接指定することも可能です：

```bash
twlogeye start --sigmaPacks windows-essential,linux-auth
```

### CLI による確認とテスト
```bash
# 利用可能なパックの一覧とルール数を表示
twlogeye sigma packs

# 有効化されているルールをパック別・出所別に一覧表示
twlogeye sigma list --sigmaPacks windows-essential,linux-auth

# 特定パックのルールのみをフィルタ表示
twlogeye sigma list --sigmaPacks windows-essential,linux-auth --pack linux-auth

# ルールのマッチングテスト
twlogeye sigma test --sigmaPacks windows-essential '{"Event":{"System":{"EventID":4625}}}'
```

---

## 2. ルールパック一覧

| パック名 | ルール数 | 対象ログソース | 主な検知対象・目的 |
| :--- | :---: | :--- | :--- |
| **`windows-essential`** | 12 | Windows Event (Security, System, Defender) | ログオン失敗、ログ消去、新規サービス登録、Defender無効化、PowerShell難読化等 |
| **`windows-ad`** | 8 | Windows Event (Security / AD DC) | Kerberoasting、AS-REP Roasting、DCSync、ドメイン信頼関係改変、GPO変更等 |
| **`windows-client`** | 8 | Windows Event (Security, TerminalServices) | 不審なRDP接続、UACバイパス、USBストレージ接続、LSASSメモリダンプ兆候等 |
| **`linux-auth`** | 6 | Linux Syslog (sshd, sudo, useradd) | SSHブルートフォース、不正ユーザーSSH、root直接ログイン、sudo認証失敗等 |
| **`linux-system`** | 7 | Linux Syslog (cron, systemd, shadow, ufw) | cronジョブ改変、systemd追加、passwd/shadow改ざん、ファイアウォール停止等 |
| **`network-threats`** | 8 | Syslog (Fortinet, Cisco, Yamaha, Palo Alto) | VPN認証失敗、管理WebUI/SSHログイン失敗、ポートスキャン、コンフィグ変更等 |
| **`web-attacks`** | 8 | Web/Proxy アクセスログ (Syslog / OTel) | Log4Shell、パストラバーサル、SQLi、WebShell、脆弱性スキャナーUA、XSS等 |

---

## 3. 各パックの詳細と収録ルール

### `windows-essential`
Windows サーバーやクライアントの**標準イベントログ（Sysmon 等の追加エージェント不要）**で検知できる最重要セキュリティイベントを集約したパックです。

- **対象ログ**: Windows Event Log (`Security`, `System`, `Microsoft-Windows-Windows Defender/Operational`)
- **目的**: 侵入直後の偵察、特権奪取、防衛機能の妨害、ランサムウェア等の破壊活動の即時検知。
- **効果**: 攻撃者が侵害を試みる初期〜中期段階での早期発見と被害拡大防止。

#### 収録ルール一覧 (12件)

| ルールタイトル | 対象イベント / 条件 | レベル | 目的とセキュリティ効果 | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Windows Failed Logon Attempt** | EventID 4625 (Security) | `low` | パスワード総当たり（ブルートフォース）やパスワードスプレー攻撃を検知。 | T1110 (Credential Access) |
| **User Account Created** | EventID 4720 (Security) | `medium` | 不正なローカルアカウント作成による永続化（バックドア）を検知。 | T1136.001 (Persistence) |
| **Member Added to Security Group** | EventID 4728, 4732, 4756 | `high` | Administrators などの特権グループへの不正なメンバー追加を検知。 | T1098 (Privilege Escalation) |
| **Special Privileges Assigned to New Logon** | EventID 4672 (Security) | `low` | 管理者権限（SeDebugPrivilege 等）の行使を監視・監査。 | T1078 (Privilege Escalation) |
| **Security Event Log Cleared** | EventID 1102 (Security) | `high` | 攻撃者による侵入痕跡消去（監査ログクリア）を検知。 | T1070.001 (Defense Evasion) |
| **System Event Log Cleared** | EventID 104 (System) | `high` | システムイベントログのクリアによる痕跡消去を検知。 | T1070.001 (Defense Evasion) |
| **Windows Defender Real-time Protection Disabled** | EventID 5001 (WinDefend) | `high` | マルウェア実行前にアンチウイルス保護が無効化された異常を検知。 | T1562.001 (Defense Evasion) |
| **New Windows Service Installed** | EventID 7045 (System) | `medium` | PsExec や悪意あるバックドアサービスの新規インストールを検知。 | T1543.003 (Persistence) |
| **Scheduled Task Created** | EventID 4698 (Security) | `medium` | スケジュールタスクの登録による自動起動・永続化を検知。 | T1053.005 (Persistence) |
| **Suspicious PowerShell Execution** | EventID 4688 (`-enc`, `DownloadString`, `iex`) | `high` | 難読化 PowerShell や外部からのインメモリコード実行を検知。 | T1059.001 (Execution) |
| **Certutil Remote File Download** | EventID 4688 (`certutil` + `urlcache`) | `high` | LOLBAS（標準コマンドの悪用）による外部からのマルウェアダウンロードを検知。 | T1105 (Command and Control) |
| **Volume Shadow Copies Deletion Via Vssadmin** | EventID 4688 (`vssadmin` + `delete shadows`) | `critical` | ランサムウェアによるバックアップ（シャドウコピー）削除活動を検知。 | T1490 (Impact) |

---

### `windows-ad`
Active Directory ドメイン環境における**ドメインコントローラ特有の脅威や横展開（Lateral Movement）**を検知するパックです。

- **対象ログ**: Windows Event Log (`Security`, Directory Service)
- **目的**: ドメイン管理者権限の奪取、Kerberos プロトコルの悪用、レプリケーション権限侵害の検知。
- **効果**: 企業ネットワーク全体が乗っ取られる最悪のインシデント（全滅シナリオ）の阻止。

#### 収録ルール一覧 (8件)

| ルールタイトル | 対象イベント / 条件 | レベル | 目的とセキュリティ効果 | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Potential Kerberoasting Attack** | EventID 4769 (TicketEncryptionType: 0x17) | `high` | SPN アカウントに対する弱い RC4 チケット要求（オフラインパスワード解析狙い）を検知。 | T1558.003 (Credential Access) |
| **Potential AS-REP Roasting Attack** | EventID 4768 (PreAuthType: 0) | `medium` | 事前認証不要アカウントに対するチケット要求（オフライン解析狙い）を検知。 | T1558.004 (Credential Access) |
| **Potential DCSync Active Directory Replication** | EventID 4662 (AccessMask: 0x100) | `high` | Mimikatz 等によるドメイン管理者パスワードハッシュ一括抽出（DCSync）を検知。 | T1003.006 (Credential Access) |
| **Domain Trust Relationship Modified** | EventID 4706, 4716 | `high` | ドメイン信頼関係の不正な作成・変更（悪意ある外部ドメインとの結合）を検知。 | T1484 (Persistence) |
| **User Password Reset Attempt** | EventID 4724 | `low` | 管理者によるパスワード強制リセットの集中発生を監視。 | T1098 (Persistence) |
| **User Account Unlocked** | EventID 4767 | `low` | ブルートフォース等でロックされたアカウントの解除操作を監査。 | T1098 (Persistence) |
| **Computer Account Created in Domain** | EventID 4741 | `low` | ドメインへの新規コンピュータ追加（偽装マシンや踏み台）を検知。 | T1136.002 (Persistence) |
| **Group Policy Object Modified** | EventID 5136, 5137 | `medium` | ドメイン全体に悪意あるスクリプトや設定を配布する GPO 改ざんを検知。 | T1484.001 (Persistence) |

---

### `windows-client`
一般 PC 端末や VDI 環境、リモートワーク端末における**不審な操作・侵入拡大活動**を検知するパックです。

- **対象ログ**: Windows Event Log (`Security`, `System`, TerminalServices, DriverFrameworks)
- **目的**: 踏み台化された端末からの内部展開、特権昇格、情報持ち出しの検知。
- **効果**: エンドポイントレベルでの不審な振る舞いの早期封じ込め。

#### 収録ルール一覧 (8件)

| ルールタイトル | 対象イベント / 条件 | レベル | 目的とセキュリティ効果 | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Remote Desktop (RDP) Logon Detected** | EventID 4624 (LogonType 10) | `low` | リモートデスクトップ経由での対話型ログオンを監視・可視化。 | T1021.001 (Lateral Movement) |
| **Terminal Services RDP Connection Established** | EventID 1149 (TerminalServices) | `low` | RDP ネットワーク接続の確立を追跡。 | T1021.001 (Lateral Movement) |
| **UAC Bypass Via Fodhelper** | EventID 4688 (`fodhelper`) | `high` | ユーザーへの確認ダイアログを出さずに管理者権限へ昇格する手口を検知。 | T1548.002 (Privilege Escalation) |
| **UAC Bypass Via Event Viewer** | EventID 4688 (`eventvwr.exe`) | `low` | レジストリハイジャックを用いた UAC バイパスの試行を検知。 | T1548.002 (Privilege Escalation) |
| **USB Storage Device Plugged In** | EventID 20001, 20003 | `low` | 私物 USB や未許可ストレージの接続による情報漏洩・マルウェア侵入を監視。 | T1052.001 (Initial Access / Exfiltration) |
| **LSASS Memory Dump Attempt** | EventID 4688 (`lsass` + `dump`) | `critical` | procdump 等で LSASS プロセスメモリをダンプし平文パスワードを盗む手口を検知。 | T1003.001 (Credential Access) |
| **BITSAdmin File Transfer Execution** | EventID 4688 (`bitsadmin` + `/transfer`) | `medium` | バックグラウンドインテリジェント転送サービスを悪用した不正ファイル取得を検知。 | T1197 (Defense Evasion) |
| **Network Share Object Added** | EventID 5142 | `low` | マルウェア配布や横展開目的の不審な共有フォルダ作成を検知。 | T1021.002 (Lateral Movement) |

---

### `linux-auth`
Linux サーバーに対する**SSH ログインや sudo などの認証・特権昇格イベント**を検知するパックです。

- **対象ログ**: Linux Syslog (`/var/log/auth.log`, `/var/log/secure`, systemd journal)
- **目的**: 外部からの不正アクセス、総当たり攻撃、管理者権限の不正奪取の検知。
- **効果**: インターネット公開サーバーや社内重要 Linux サーバーの不正ログイン防止。

#### 収録ルール一覧 (6件)

| ルールタイトル | 対象キーワード / 条件 | レベル | 目的とセキュリティ効果 | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **SSH Failed Password Authentication** | `Failed password for` | `low` | SSH パスワード認証失敗（ブルートフォース攻撃）を検知。 | T1110 (Credential Access) |
| **SSH Login Attempt With Invalid User** | `Failed password for invalid user` | `medium` | 存在しないユーザー名でのログイン試行（アカウント探索攻撃）を検知。 | T1110 (Credential Access) |
| **Direct SSH Root Login Accepted** | `Accepted password for root` / `Accepted publickey for root` | `medium` | 本来禁止されるべき root アカウントへの直接 SSH ログイン成功を監視。 | T1078.003 (Initial Access) |
| **Sudo Authentication Failure** | `authentication failure`, `incorrect password attempt` | `medium` | 一般ユーザーからの不正な sudo 実行や内部不正を検知。 | T1548.003 (Privilege Escalation) |
| **Sudoers Configuration File Modified** | `etc/sudoers`, `visudo` | `high` | 特権昇格ルールの改ざん（NOPASSWD 付与など）を検知。 | T1548.003 (Privilege Escalation) |
| **New Linux User Account Created** | `new user: name=`, `useradd` | `medium` | 不正なバックドアアカウントの追加を検知。 | T1136.001 (Persistence) |

---

### `linux-system`
Linux サーバーへの侵入成功後に行われる**「永続化（自動起動設置）」「設定改ざん」「セキュリティ停止」**を検知するパックです。

- **対象ログ**: Linux Syslog (`syslog`, `messages`, `daemon.log`, `kern.log`)
- **目的**: バックドアの設置、パスワードファイル改変、ファイアウォール無効化の検知。
- **効果**: 侵入されたことに気づきにくい潜伏型マルウェアや C2 通信の早期発見。

#### 収録ルール一覧 (7件)

| ルールタイトル | 対象キーワード / 条件 | レベル | 目的とセキュリティ効果 | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Cron Job Created or Modified** | `REPLACE (`, `crontab[`, `/etc/cron` | `low` | cron による定期実行タスクの登録（バックドアの再接続など）を検知。 | T1053.003 (Persistence) |
| **Systemd Service Installed or Started** | `Created symlink /etc/systemd/system/`, `systemd: Started` | `low` | systemd サービスファイルの配置による自動起動登録を検知。 | T1543.002 (Persistence) |
| **Password File Modified or Password Changed** | `password changed for`, `/etc/shadow` | `low` | パスワード変更やシャドウパスワードファイルの改変を監査。 | T1098 (Persistence) |
| **Linux Host Firewall Stopped or Flushed** | `ufw stop`, `firewalld: stopped`, `iptables -F` | `medium` | 防御壁（ホストファイアウォール）の無効化を検知。 | T1562.004 (Defense Evasion) |
| **Linux User Account Deleted** | `delete user`, `userdel` | `low` | 痕跡消去や業務妨害目的のアカウント削除を検知。 | T1531 (Impact) |
| **New Linux Group Created** | `new group: name=`, `groupadd` | `low` | 不審な新規グループ作成を検知。 | T1136.001 (Persistence) |
| **Unsigned or Out-of-Tree Kernel Module Loaded** | `loading out-of-tree module`, `module verification failed` | `medium` | ルートキット等の未検証カーネルモジュールロードを検知。 | T1547.006 (Persistence) |

---

### `network-threats`
Fortinet (FortiGate)、Cisco (IOS / ASA)、Yamaha ルーター、Palo Alto 等の**ネットワーク機器・UTM・ファイアウォールログ**を監視するパックです。

- **対象ログ**: Syslog (UDP/TCP 514 番ポートで受信したネットワーク機器ログ)
- **目的**: 外部からの不正侵入試行、VPN 認証攻撃、スキャン活動、機器設定変更の検知。
- **効果**: ネットワーク境界（エッジ）での脅威をリアルタイムに遮断・対応。

#### 収録ルール一覧 (8件)

| ルールタイトル | 対象キーワード / 条件 | レベル | 目的とセキュリティ効果 | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **VPN Authentication Failed** | `VPN authentication failed`, `IPsec authentication failed` | `medium` | リモートアクセス VPN への認証総当たりを検知。 | T1110 (Initial Access) |
| **FortiGate SSL VPN Authentication Failure** | `action=ssl-login-fail`, `SSL VPN login fail` | `medium` | FortiGate 機器への SSL-VPN ログイン失敗を検知。 | T1110 (Initial Access) |
| **Cisco Device Authentication Failure** | `%SEC_LOGIN-4-LOGIN_FAILED`, `%AAA-3-BADAUTH` | `medium` | Cisco ルーター/スイッチ/ASA への不正ログインを検知。 | T1110 (Credential Access) |
| **Yamaha Router Authentication Failure** | `Login failed`, `rejected TELNET`, `rejected SSH` | `medium` | Yamaha ルーター（RTX/NVRシリーズ）への不正アクセスを検知。 | T1110 (Credential Access) |
| **Firewall Admin Console Login Failure** | `admin login failed`, `WebUI login failed` | `medium` | ファイアウォール管理画面（GUI/SSH）への侵入試行を検知。 | T1110 (Credential Access) |
| **Network Scan or Deny Flood** | `port scan`, `SYN flood`, `IP spoofing`, `LAND attack` | `high` | 外部からの偵察スキャン活動や DoS 攻撃の兆候を検知。 | T1046 (Discovery) |
| **Palo Alto Networks Threat Detected** | `,THREAT,`, `,vulnerability,`, `,spyware,` | `high` | Palo Alto NGFW が検知した既知のマルウェアや脅威ログを通知。 | T1190 (Initial Access) |
| **Network Device Configuration Changed** | `configuration changed`, `config commit`, `save config` | `low` | ルーター・FW の設定変更ログを自動監査。 | T1565 (Defense Evasion) |

---

### `web-attacks`
Apache、Nginx、リバースプロキシ等の**Web アクセスログに現れる典型的な攻撃パターン**を検知するパックです。

- **対象ログ**: Web サーバーアクセスログ (Syslog 転送 または OpenTelemetry)
- **目的**: Web アプリケーションの脆弱性悪用、WebShell 設置、自動スキャナーの検知。
- **効果**: DMZ や公開サーバーに対するサイバー攻撃の初期兆候を即座に捕捉。

#### 収録ルール一覧 (8件)

| ルールタイトル | 対象キーワード / 条件 | レベル | 目的とセキュリティ効果 | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Log4j JNDI Exploit Attempt (Log4Shell)** | `${jndi:ldap:`, `${jndi:rmi:`, `${jndi:dns:` | `critical` | 深刻な脆弱性 Log4Shell (CVE-2021-44228) の悪用試行を確実に検知。 | T1190 (Initial Access) |
| **Path Traversal Attempt** | `/../`, `/etc/passwd`, `win.ini`, `%2e%2e%2f` | `high` | サーバー内の機密ファイル閲覧を狙うディレクトリスキームを検知。 | T1190 (Initial Access) |
| **SQL Injection Attempt** | `UNION SELECT`, `' OR 1=1`, `WAITFOR DELAY` | `high` | データベース奪取を狙う SQL インジェクション攻撃を検知。 | T1190 (Initial Access) |
| **WebShell Access or Execution** | `eval(base64_decode`, `c99.php`, `r57.php`, `wso.php` | `critical` | 設置されたバックドア（WebShell）へのアクセスや遠隔操作を検知。 | T1505.003 (Persistence) |
| **Web Vulnerability Scanner User-Agent** | `Nikto`, `sqlmap`, `gobuster`, `dirbuster`, `Acunetix` | `medium` | 自動攻撃ツールによる事前調査・脆弱性探索アクティビティを検知。 | T1595.002 (Discovery) |
| **Cross Site Scripting (XSS) Pattern** | `<script>`, `javascript:alert(`, `<svg/onload=` | `medium` | クライアント攻撃を狙う XSS ペイロードの送信を検知。 | T1190 (Initial Access) |
| **Spring4Shell Remote Code Execution Attempt** | `class.module.classLoader` | `critical` | Spring Framework の RCE 脆弱性 (CVE-2022-22965) 悪用を検知。 | T1190 (Initial Access) |
| **PHP Information Disclosure Access (phpinfo)** | `phpinfo.php`, `info.php`, `?phpinfo=` | `low` | 攻撃者によるサーバー環境情報の偵察活動を検知。 | T1592.002 (Discovery) |

---

## 4. カスタムルールとの併用と優先度オーバーライド

組み込みパックを使用しながら、独自のルールファイル（`sigmaRules`）や WebAPI/MCP から追加したルールを併用できます。

### 優先度ルール
同じ `id`（UUID）を持つルールが重複した場合、以下の優先順位に従って**上位のルールが自動的に下位のルールを上書き（オーバーライド）**します：

1. **`db`**（最高優先度: MCP や API から動的に追加されたルール）
2. **`file:` / `embed:`**（高優先度: `sigmaRules` で指定した外部カスタムルール）
3. **`pack:`**（標準優先度: 組み込みルールパック）

### 活用例（ルールのチューニング）
組み込みパックのルール（例: `win_security_failed_logons`）をそのまま使いたいが、「特定の社内 IP や開発アカウントを除外したい」「重要度レベルを `low` から `high` に引き上げたい」という場合、同じ ID を持つ YAML ファイルを自作して `sigmaRules` に指定するだけで、**組み込みパック側のルールが自動的にカスタムルールで置き換わります**。

---

## 5. Wazuh ルールパックおよびルール変換・相関検知

twlogeye は、オープンソース SIEM である [Wazuh](https://github.com/wazuh/wazuh) の膨大なルールセット資産を Sigma ルールとして取り込み、活用するための機能を標準で備えています。

### 組み込み Wazuh ルールパック

| パック名 | 主な対象 | 収録ルール | 相関検知 |
| :--- | :--- | :--- | :---: |
| **`wazuh-linux`** | Linux (SSHD, Sudo, PAM) | 不正ユーザ認証試行、ブルートフォース攻撃、sudo特権昇格、sudoers未登録実行、PAM認証失敗 | 対応 (SSHD総当たり等) |
| **`wazuh-web`** | Web (Apache, Nginx) | 脆弱性スキャナー (Nikto/sqlmap等)、機密隠しファイル (.git/.env/.htpasswd) 探索 | - |
| **`wazuh-network`** | ネットワーク機器 (Cisco, FortiGate) | Cisco 管理画面認証失敗、FortiGate SSL-VPN 複数回連続認証失敗 | 対応 (VPN総当たり等) |

### Wazuh ルール XML の Sigma 変換コマンド (`convert-wazuh`)

手元の Wazuh ルール XML ファイルや公式リポジトリのルールセットを、twlogeye で利用可能な Sigma YAML ルールへ変換できます。`<if_sid>` による親ルールの階層条件は自動的に AND 展開され、`<frequency>` / `<timeframe>` による相関条件も保持されます。

```bash
# 単一の Wazuh ルール XML を Sigma YAML に変換
twlogeye sigma convert-wazuh -o ./my-rules ./0095-sshd_rules.xml

# ディレクトリ内の全 XML を一括変換
twlogeye sigma convert-wazuh -o ./my-rules /path/to/wazuh/ruleset/rules/

# 標準出力へ YAML を出力（パイプ処理用）
twlogeye sigma convert-wazuh --stdout ./0095-sshd_rules.xml
```

### Wazuh デコーダ XML の正規表現変換コマンド (`convert-wazuh-decoder`)

Wazuh のデコーダ定義（`<prematch>`, `<regex>`, `<order>`）から、twlogeye の NamedCaptures で使用できる名前付きキャプチャグループ正規表現を自動生成します。

```bash
# デコーダ XML を変換してファイルに出力
twlogeye sigma convert-wazuh-decoder -o ./captures ./0310-ssh_decoders.xml

# 標準出力に出力して確認
twlogeye sigma convert-wazuh-decoder --stdout ./0310-ssh_decoders.xml
```

### スライディングウィンドウによる相関検知（案A）

変換された Sigma ルールに含まれる `correlation:` メタデータ（`frequency`, `timeframe`, `group_by`）を twlogeye の `auditor` が解釈し、インメモリのスライディング時間窓で同一送信元（`client`）等からの発生頻度を監視します。指定時間枠内に指定回数以上イベントが発生した時点でアラート通知（`Notify`）がトリガーされます。

