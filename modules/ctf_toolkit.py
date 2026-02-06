import asyncio
import sys
import re
from typing import Optional


class CTFToolkit:
    """CTF競技用ツールキット - 各種セキュリティツールをMCP経由で実行"""

    def __init__(self):
        self.default_timeout = 300  # 5分

    async def _run_command(self, cmd: list, timeout: int = None) -> str:
        """コマンドを非同期で実行し、結果を返す"""
        if timeout is None:
            timeout = self.default_timeout

        try:
            print(f"Executing: {' '.join(cmd)}", file=sys.stderr)

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

            if process.returncode == 0:
                return output if output else error
            else:
                return f"Command finished with return code {process.returncode}\n\nOutput:\n{output}\n\nErrors:\n{error}"

        except asyncio.TimeoutError:
            return f"Command timed out after {timeout} seconds"
        except Exception as e:
            return f"Error executing command: {str(e)}"

    # =========================================================================
    # Web攻撃ツール
    # =========================================================================

    async def sqlmap_scan(self, url: str, options: Optional[str] = None) -> str:
        """SQLmapでSQLインジェクション脆弱性をスキャン

        Args:
            url: テスト対象のURL（パラメータ付き）
            options: 追加オプション（例: "--dbs", "--tables"）
        """
        cmd = ["sqlmap", "-u", url, "--batch", "--random-agent"]
        if options:
            cmd.extend(options.split())

        result = await self._run_command(cmd, timeout=600)
        return f"=== SQLmap Scan Results ===\nTarget: {url}\n\n{result}"

    async def nikto_scan(self, target: str) -> str:
        """Niktoでwebサーバーの脆弱性をスキャン

        Args:
            target: ターゲットURL（例: http://example.com）
        """
        cmd = ["nikto", "-h", target, "-nointeractive"]
        result = await self._run_command(cmd, timeout=600)
        return f"=== Nikto Scan Results ===\nTarget: {target}\n\n{result}"

    async def gobuster_dir(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """Gobusterでディレクトリ列挙

        Args:
            url: ターゲットURL
            wordlist: 使用するワードリスト
        """
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "20"]
        result = await self._run_command(cmd, timeout=300)
        return f"=== Gobuster Directory Scan ===\nTarget: {url}\nWordlist: {wordlist}\n\n{result}"

    async def wfuzz_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """Wfuzzでファジング実行

        Args:
            url: ターゲットURL（FUZZをプレースホルダーとして使用）
            wordlist: 使用するワードリスト
        """
        # URLにFUZZが含まれていない場合は自動追加
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        cmd = ["wfuzz", "-c", "-z", f"file,{wordlist}", "--hc", "404", url]
        result = await self._run_command(cmd, timeout=300)
        return f"=== Wfuzz Fuzzing Results ===\nTarget: {url}\n\n{result}"

    async def whatweb_scan(self, url: str) -> str:
        """WhatWebでWeb技術を検出

        Args:
            url: ターゲットURL
        """
        cmd = ["whatweb", "-a", "3", url]
        result = await self._run_command(cmd, timeout=120)
        return f"=== WhatWeb Technology Detection ===\nTarget: {url}\n\n{result}"

    # =========================================================================
    # パスワード解析ツール
    # =========================================================================

    async def john_crack(self, hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", format_type: Optional[str] = None) -> str:
        """John the Ripperでハッシュを解読

        Args:
            hash_file: ハッシュファイルのパス
            wordlist: 使用するワードリスト
            format_type: ハッシュ形式（例: "md5", "sha256", "raw-md5"）
        """
        cmd = ["john", f"--wordlist={wordlist}"]
        if format_type:
            cmd.append(f"--format={format_type}")
        cmd.append(hash_file)

        result = await self._run_command(cmd, timeout=600)

        # 結果を表示
        show_cmd = ["john", "--show", hash_file]
        show_result = await self._run_command(show_cmd, timeout=30)

        return f"=== John the Ripper Results ===\nHash File: {hash_file}\n\nCracking Output:\n{result}\n\nCracked Passwords:\n{show_result}"

    async def hydra_attack(self, target: str, service: str, username: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
        """Hydraでブルートフォース攻撃

        Args:
            target: ターゲットホスト
            service: サービス（ssh, ftp, http-post-form等）
            username: ユーザー名（または-Lでユーザーリスト）
            wordlist: パスワードワードリスト
        """
        cmd = ["hydra", "-l", username, "-P", wordlist, "-t", "4", "-vV", target, service]
        result = await self._run_command(cmd, timeout=600)
        return f"=== Hydra Brute Force Results ===\nTarget: {target}\nService: {service}\nUsername: {username}\n\n{result}"

    # =========================================================================
    # フォレンジック・ステガノグラフィ
    # =========================================================================

    async def binwalk_extract(self, file_path: str) -> str:
        """Binwalkでファイル内の埋め込みデータを抽出

        Args:
            file_path: 解析対象ファイル
        """
        # まず解析
        cmd_analyze = ["binwalk", file_path]
        analyze_result = await self._run_command(cmd_analyze, timeout=120)

        # 抽出も実行
        cmd_extract = ["binwalk", "-e", file_path]
        extract_result = await self._run_command(cmd_extract, timeout=120)

        return f"=== Binwalk Analysis ===\nFile: {file_path}\n\nEmbedded Files Found:\n{analyze_result}\n\nExtraction:\n{extract_result}"

    async def foremost_recover(self, file_path: str, output_dir: str = "/tmp/foremost_output") -> str:
        """Foremostでファイル復元

        Args:
            file_path: 解析対象ファイル
            output_dir: 出力ディレクトリ
        """
        cmd = ["foremost", "-i", file_path, "-o", output_dir, "-T"]
        result = await self._run_command(cmd, timeout=300)

        # 出力ディレクトリの内容を確認
        ls_cmd = ["ls", "-la", output_dir]
        ls_result = await self._run_command(ls_cmd, timeout=30)

        return f"=== Foremost File Recovery ===\nInput: {file_path}\nOutput: {output_dir}\n\n{result}\n\nRecovered Files:\n{ls_result}"

    async def steghide_extract(self, file_path: str, passphrase: str = "") -> str:
        """Steghideで隠しデータを抽出

        Args:
            file_path: 対象ファイル（JPEG, BMP, WAV, AU）
            passphrase: パスフレーズ（空の場合はパスフレーズなし）
        """
        cmd = ["steghide", "extract", "-sf", file_path, "-f"]
        if passphrase:
            cmd.extend(["-p", passphrase])
        else:
            cmd.extend(["-p", ""])

        result = await self._run_command(cmd, timeout=60)
        return f"=== Steghide Extraction ===\nFile: {file_path}\n\n{result}"

    async def exiftool_analyze(self, file_path: str) -> str:
        """ExifToolでメタデータを解析

        Args:
            file_path: 解析対象ファイル
        """
        cmd = ["exiftool", file_path]
        result = await self._run_command(cmd, timeout=60)
        return f"=== ExifTool Metadata Analysis ===\nFile: {file_path}\n\n{result}"

    async def strings_extract(self, file_path: str, min_length: int = 4) -> str:
        """Stringsでファイルから文字列を抽出

        Args:
            file_path: 対象ファイル
            min_length: 最小文字列長
        """
        cmd = ["strings", "-n", str(min_length), file_path]
        result = await self._run_command(cmd, timeout=60)

        # 出力が長すぎる場合は切り詰め
        lines = result.split('\n')
        if len(lines) > 200:
            result = '\n'.join(lines[:200]) + f"\n\n... (truncated, {len(lines)} total lines)"

        return f"=== Strings Extraction ===\nFile: {file_path}\nMin Length: {min_length}\n\n{result}"

    # =========================================================================
    # リバースエンジニアリング
    # =========================================================================

    async def radare2_analyze(self, file_path: str) -> str:
        """Radare2でバイナリ解析

        Args:
            file_path: 解析対象バイナリ
        """
        # 基本情報を取得
        cmd = ["r2", "-q", "-c", "iI; afl; pdf @ main", file_path]
        result = await self._run_command(cmd, timeout=120)
        return f"=== Radare2 Binary Analysis ===\nFile: {file_path}\n\n{result}"

    async def objdump_disasm(self, file_path: str) -> str:
        """Objdumpで逆アセンブル

        Args:
            file_path: 対象バイナリ
        """
        cmd = ["objdump", "-d", "-M", "intel", file_path]
        result = await self._run_command(cmd, timeout=120)

        # 出力が長すぎる場合は切り詰め
        lines = result.split('\n')
        if len(lines) > 500:
            result = '\n'.join(lines[:500]) + f"\n\n... (truncated, {len(lines)} total lines)"

        return f"=== Objdump Disassembly ===\nFile: {file_path}\n\n{result}"

    async def ltrace_run(self, command: str) -> str:
        """Ltraceでライブラリコールをトレース

        Args:
            command: 実行するコマンド
        """
        cmd = ["ltrace", "-f"] + command.split()
        result = await self._run_command(cmd, timeout=60)
        return f"=== Ltrace Library Call Trace ===\nCommand: {command}\n\n{result}"

    # =========================================================================
    # ネットワーク解析
    # =========================================================================

    async def tshark_analyze(self, pcap_file: str, filter_expr: Optional[str] = None) -> str:
        """Tsharkでパケット解析

        Args:
            pcap_file: PCAPファイルのパス
            filter_expr: 表示フィルタ（例: "http", "tcp.port==80"）
        """
        cmd = ["tshark", "-r", pcap_file]
        if filter_expr:
            cmd.extend(["-Y", filter_expr])
        cmd.extend(["-c", "100"])  # 最初の100パケットのみ

        result = await self._run_command(cmd, timeout=120)
        return f"=== Tshark Packet Analysis ===\nFile: {pcap_file}\nFilter: {filter_expr or 'None'}\n\n{result}"

    async def netcat_connect(self, host: str, port: int, data: Optional[str] = None) -> str:
        """Netcatで接続

        Args:
            host: 接続先ホスト
            port: ポート番号
            data: 送信するデータ
        """
        if data:
            cmd = ["bash", "-c", f"echo '{data}' | nc -w 5 {host} {port}"]
        else:
            cmd = ["nc", "-w", "5", host, str(port)]

        result = await self._run_command(cmd, timeout=30)
        return f"=== Netcat Connection ===\nHost: {host}:{port}\n\n{result}"

    # =========================================================================
    # 暗号解読
    # =========================================================================

    async def openssl_decrypt(self, file_path: str, cipher: str, password: str) -> str:
        """OpenSSLで復号

        Args:
            file_path: 暗号化されたファイル
            cipher: 暗号方式（例: aes-256-cbc）
            password: パスワード
        """
        cmd = ["openssl", cipher, "-d", "-in", file_path, "-pass", f"pass:{password}"]
        result = await self._run_command(cmd, timeout=30)
        return f"=== OpenSSL Decryption ===\nFile: {file_path}\nCipher: {cipher}\n\n{result}"

    async def base64_decode(self, data: str) -> str:
        """Base64デコード

        Args:
            data: Base64エンコードされた文字列
        """
        cmd = ["bash", "-c", f"echo '{data}' | base64 -d"]
        result = await self._run_command(cmd, timeout=10)
        return f"=== Base64 Decode ===\nInput: {data[:50]}...\n\nDecoded:\n{result}"

    # =========================================================================
    # ステータス確認
    # =========================================================================

    async def get_status(self) -> str:
        """CTFツールキットの状態を確認"""
        tools = [
            ("sqlmap", ["sqlmap", "--version"]),
            ("nikto", ["nikto", "-Version"]),
            ("gobuster", ["gobuster", "version"]),
            ("john", ["john", "--help"]),
            ("hydra", ["hydra", "-h"]),
            ("binwalk", ["binwalk", "--help"]),
            ("steghide", ["steghide", "--version"]),
            ("exiftool", ["exiftool", "-ver"]),
            ("radare2", ["r2", "-v"]),
            ("tshark", ["tshark", "--version"]),
        ]

        results = ["=== CTF Toolkit Status ===\n"]
        for name, cmd in tools:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=5)
                results.append(f"✅ {name}: Available")
            except:
                results.append(f"❌ {name}: Not available")

        return "\n".join(results)
