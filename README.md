# Hacking MCP - 自律型セキュリティ研究AI

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![MCP](https://img.shields.io/badge/MCP-Integrated-green.svg)](https://github.com/anthropics/mcp)

> **⚠️ 研究目的専用**: このツールは教育・セキュリティ研究目的で提供されています。許可のないシステムへの使用は違法です。

Claude DesktopとDockerを活用した**自律型セキュリティ研究AI**です。
自動偵察、エクスプロイト開発支援、権限昇格、ファジングなど、包括的なペネトレーションテスト機能を提供します。

---

## 🚀 主要機能

### 🤖 自律ハッキング機能（NEW!）

| モジュール              | 機能                                                       |
| ----------------------- | ---------------------------------------------------------- |
| **Payload Arsenal**     | 60+種類のペイロード（リバースシェル、Webシェル、msfvenom） |
| **Exploit Development** | シェルコード生成、ROP/ヒープ/FSBテンプレート               |
| **Auto Reconnaissance** | 完全自動偵察、攻撃面分析、次アクション提案                 |
| **Post-Exploitation**   | Linux/Windows権限昇格、クレデンシャルハンティング          |
| **Fuzzer**              | BOF/FSB検出、SQLi/XSS/LFI/SSTIファジング                   |
| **Memory Module**       | セッション記録、学習ベースの推奨                           |

### 🔍 偵察・スキャン機能

- **Nmapスキャン** - ポートスキャン、サービス検出、バージョン特定
- **Webスキャン** - HTTPヘッダー分析、ディレクトリ列挙、技術検出
- **DNS調査** - レコード取得、サブドメイン列挙、逆引きDNS

### 🏁 CTF支援機能

- **CTF Intelligence** - 暗号、フォレンジック、Web、Pwn自動分析
- **CTF Strategy** - 問題分類、戦略立案、チェックリスト生成
- **CTF Toolkit** - sqlmap, binwalk, steghide, zsteg等の統合ツール

---

## 📋 必要条件

- **Claude Desktop** 最新バージョン
- **Docker** 20.10以上
- **OS**: Windows 10/11、macOS、Linux
- **メモリ**: 推奨8GB以上
- **ディスク**: 10GBの空き容量

---

## 🛠️ セットアップ

### 1. クローン

```bash
git clone https://github.com/makin0n/hacking-mcp.git
cd hacking-mcp
```

### 2. Dockerビルド

```bash
docker build -t hacking-mcp .
```

### 3. Claude Desktop設定

`%APPDATA%\Claude\claude_desktop_config.json` (Windows) に追加:

```json
{
  "mcpServers": {
    "hacking-mcp": {
      "command": "docker",
      "args": ["run", "--rm", "--network", "host", "-i", "hacking-mcp"]
    }
  }
}
```

### 4. Claude Desktopを再起動

---

## 📖 使用例

### 🤖 自律ハッキング

```
# 完全自動偵察
10.10.10.100を自律偵察して

# リバースシェル生成
bashのリバースシェルを10.10.14.1:4444で作って

# 権限昇格チェック
Linux権限昇格チェックコマンドを教えて

# BOFエクスプロイト生成
オフセット264、ターゲット0x401234でBOFエクスプロイトを生成して

# セッション開始と記録
10.10.10.100のペンテストセッションを開始して
```

### 🔍 偵察・スキャン

```
# ポートスキャン
192.168.1.100をスキャンして

# Webスキャン
https://example.comのWebセキュリティ監査を実行して

# DNS調査
example.comの包括的DNS調査を実行して
```

### 🏁 CTF支援

```
# CTF問題分析
このCTF問題を分析して: base64エンコードされたデータ...

# CTF戦略アドバイス
このCrypto問題の解き方を教えて

# フォレンジック解析
このPNG画像をステガノグラフィ解析して
```

---

## 📁 プロジェクト構造

```
hacking-mcp/
├── main.py                    # メインMCPサーバー（100+ツールエンドポイント）
├── Dockerfile                 # Docker設定
├── requirements.txt           # Python依存関係
├── modules/
│   ├── nmap_scanner.py        # Nmapスキャン
│   ├── web_scanner.py         # Webスキャン
│   ├── dns_scanner.py         # DNS調査
│   ├── ssh_explorer.py        # SSH調査
│   ├── service_analyzer.py    # サービス分析
│   ├── ctf_toolkit.py         # CTFツールキット
│   ├── ctf_intelligence.py    # CTF AI分析
│   ├── ctf_strategy.py        # CTF戦略アドバイザー
│   ├── payload_arsenal.py     # ペイロード生成 (NEW)
│   ├── exploit_dev.py         # エクスプロイト開発 (NEW)
│   ├── auto_recon.py          # 自動偵察 (NEW)
│   ├── post_exploit.py        # ポストエクスプロイト (NEW)
│   ├── fuzzer.py              # ファジング (NEW)
│   └── memory_module.py       # メモリ/学習 (NEW)
└── utils/
    └── report_manager.py      # レポート管理
```

---

## 🔧 MCPツール一覧（100+）

### Payload Arsenal

- `get_reverse_shell` - リバースシェル（bash, python, php, nc, powershell等）
- `get_webshell` - Webシェル（PHP, ASP, JSP）
- `get_msfvenom_payload` - msfvenomコマンド生成
- `get_privesc_payload` - 権限昇格ペイロード
- `get_tty_upgrade` - TTYシェルアップグレード

### Exploit Development

- `pattern_create` / `pattern_offset` - BOFオフセット特定
- `get_shellcode` - Linux x86/x64シェルコード
- `get_rop_template` - ROPエクスプロイトテンプレート
- `get_heap_template` - ヒープエクスプロイト（tcache, fastbin）
- `generate_bof_exploit` - BOFエクスプロイト自動生成

### Auto Reconnaissance

- `auto_recon_full` - 完全自動偵察
- `auto_recon_web` - Web専用偵察
- `suggest_next_action` - 次アクション提案

### Post-Exploitation

- `get_linux_privesc_checks` - Linux権限昇格コマンド
- `get_windows_privesc_checks` - Windows権限昇格コマンド
- `get_credential_locations` - クレデンシャル発見場所
- `get_kernel_exploits` - カーネル脆弱性提案
- `get_persistence_methods` - 永続化手法

### Fuzzer

- `fuzz_pattern_create` / `fuzz_pattern_offset` - パターン生成
- `fuzz_web_payloads` - SQLi/XSS/LFI/SSTI/CMDペイロード
- `fuzz_wfuzz_command` - wfuzzコマンド生成

### Memory Module

- `memory_start_session` - セッション開始
- `memory_record_action` - アクション記録
- `memory_suggest` - 履歴ベース推奨

---

## ⚠️ 法的・倫理的注意事項

- **許可されたシステムでのみ使用**してください
- **教育・研究目的**での使用を想定しています
- 各国の法律・規制を遵守してください
- 不正アクセスは刑事罰の対象となります

---

## 🐛 トラブルシューティング

### Dockerビルドエラー

```bash
docker system prune -a
docker build --no-cache -t hacking-mcp .
```

### Claude Desktop接続エラー

1. 設定ファイルのパスを確認
2. Dockerイメージが正常にビルドされているか確認
3. Claude Desktopを再起動

---

## 📄 ライセンス

このプロジェクトは教育・研究目的で提供されています。
使用にあたっては、適切な法的・倫理的考慮を行ってください。

---

**⚠️ 免責事項**: このツールの使用によって生じたいかなる損害・法的問題についても、開発者は責任を負いません。
