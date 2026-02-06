"""
CTF Auto-Solver Module - 完全自律CTF問題解決

問題を与えると自動的に分類・解析・解決し、フラグのみを出力します。
研究・教育目的専用
"""

import re
import base64
import codecs
import hashlib
import struct
import asyncio
from typing import Optional, List, Dict, Tuple


class CTFSolver:
    """CTF完全自律ソルバー - フラグ抽出に特化"""

    # フラグ形式パターン（主要CTFプラットフォーム対応）
    FLAG_PATTERNS = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'THM\{[^}]+\}',
        r'SECCON\{[^}]+\}',
        r'ASIS\{[^}]+\}',
        r'CSAW\{[^}]+\}',
        r'Google\{[^}]+\}',
        r'HITCON\{[^}]+\}',
        r'DragonCTF\{[^}]+\}',
        r'rtcp\{[^}]+\}',
        r'ractf\{[^}]+\}',
        r'tjctf\{[^}]+\}',
        r'utctf\{[^}]+\}',
        r'utflag\{[^}]+\}',
        r'uiuctf\{[^}]+\}',
        r'lactf\{[^}]+\}',
    ]

    def __init__(self):
        self.verbose = False  # Trueで詳細出力、Falseでフラグのみ

    # =========================================================================
    # フラグ抽出
    # =========================================================================

    def extract_flags(self, text: str, custom_format: str = None) -> List[str]:
        """テキストからフラグを抽出

        Args:
            text: 検索対象テキスト
            custom_format: カスタムフラグ形式（例: "MYCTF{.*}"）
        """
        flags = []
        patterns = self.FLAG_PATTERNS.copy()

        if custom_format:
            patterns.insert(0, custom_format)

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)

        # 重複を除去して返す
        return list(set(flags))

    # =========================================================================
    # 暗号解読（Crypto）
    # =========================================================================

    def solve_crypto(self, data: str, hint: str = "") -> str:
        """暗号問題を自動解決

        Args:
            data: 暗号文または問題データ
            hint: ヒント（任意）
        """
        results = []
        decoded_texts = []

        # Base64
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            if decoded and self._is_printable(decoded):
                decoded_texts.append(("Base64", decoded))
        except:
            pass

        # Base64 multiple layers
        current = data
        for i in range(5):
            try:
                current = base64.b64decode(current).decode('utf-8', errors='ignore')
                if current and self._is_printable(current):
                    decoded_texts.append((f"Base64 x{i+1}", current))
            except:
                break

        # Hex
        try:
            if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                if decoded and self._is_printable(decoded):
                    decoded_texts.append(("Hex", decoded))
        except:
            pass

        # ROT13
        rot13 = codecs.decode(data, 'rot_13')
        if rot13 != data:
            decoded_texts.append(("ROT13", rot13))

        # Caesar (all shifts)
        for shift in range(1, 26):
            shifted = self._caesar_shift(data, shift)
            flags = self.extract_flags(shifted)
            if flags:
                decoded_texts.append((f"Caesar shift {shift}", shifted))

        # XOR with single byte
        try:
            data_bytes = data.encode() if isinstance(data, str) else data
            for key in range(1, 256):
                xored = bytes([b ^ key for b in data_bytes])
                try:
                    decoded = xored.decode('utf-8', errors='ignore')
                    flags = self.extract_flags(decoded)
                    if flags:
                        decoded_texts.append((f"XOR key={key}", decoded))
                except:
                    pass
        except:
            pass

        # Binary string
        if re.match(r'^[01\s]+$', data):
            try:
                binary = data.replace(' ', '')
                decoded = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
                if self._is_printable(decoded):
                    decoded_texts.append(("Binary", decoded))
            except:
                pass

        # Octal
        if re.match(r'^[0-7\s]+$', data):
            try:
                parts = data.split()
                decoded = ''.join(chr(int(p, 8)) for p in parts)
                if self._is_printable(decoded):
                    decoded_texts.append(("Octal", decoded))
            except:
                pass

        # フラグを検索して返す
        all_flags = []
        for method, text in decoded_texts:
            flags = self.extract_flags(text)
            all_flags.extend(flags)
            if not flags and self._is_printable(text):
                # フラグが見つからなくても可読テキストを記録
                results.append(f"[{method}] {text[:200]}")

        if all_flags:
            return '\n'.join(set(all_flags))
        elif results and self.verbose:
            return "フラグ未検出。デコード結果:\n" + '\n'.join(results[:5])
        else:
            return "フラグが見つかりませんでした"

    def _caesar_shift(self, text: str, shift: int) -> str:
        """シーザー暗号シフト"""
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def _is_printable(self, text: str) -> bool:
        """印刷可能な文字が多いかチェック"""
        if not text:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return printable / len(text) > 0.8

    # =========================================================================
    # フォレンジック解決
    # =========================================================================

    def solve_forensics(self, data: bytes, filename: str = "") -> str:
        """フォレンジック問題を自動解決

        Args:
            data: ファイルデータ
            filename: ファイル名（任意）
        """
        results = []
        flags = []

        # 文字列抽出してフラグ検索
        strings = self._extract_strings(data)
        for s in strings:
            found = self.extract_flags(s)
            flags.extend(found)

        # Base64パターンを検索
        b64_pattern = r'[A-Za-z0-9+/=]{20,}'
        for match in re.finditer(b64_pattern, strings):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                found = self.extract_flags(decoded)
                flags.extend(found)
            except:
                pass

        # コメントや埋め込みデータ
        if b'flag' in data.lower() if isinstance(data, bytes) else 'flag' in data.lower():
            # フラグが埋め込まれている可能性
            text = data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else data
            found = self.extract_flags(text)
            flags.extend(found)

        if flags:
            return '\n'.join(set(flags))
        elif self.verbose:
            return f"フラグ未検出。抽出文字列数: {len(strings.split(chr(10)))}"
        else:
            return "フラグが見つかりませんでした"

    def _extract_strings(self, data: bytes, min_length: int = 4) -> str:
        """バイナリから文字列を抽出"""
        result = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    result.append(''.join(current))
                current = []
        if len(current) >= min_length:
            result.append(''.join(current))
        return '\n'.join(result)

    # =========================================================================
    # Web問題解決
    # =========================================================================

    def solve_web(self, url: str = "", html: str = "", hint: str = "") -> str:
        """Web問題を自動解決

        Args:
            url: 対象URL
            html: HTMLソース
            hint: ヒント
        """
        flags = []

        # HTMLソースからフラグ検索
        if html:
            flags.extend(self.extract_flags(html))

            # コメントを検索
            comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
            for comment in comments:
                flags.extend(self.extract_flags(comment))

            # JavaScript内を検索
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
            for script in scripts:
                flags.extend(self.extract_flags(script))

            # hidden inputを検索
            hidden = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for value in hidden:
                flags.extend(self.extract_flags(value))
                # Base64でエンコードされている可能性
                try:
                    decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                    flags.extend(self.extract_flags(decoded))
                except:
                    pass

        if flags:
            return '\n'.join(set(flags))
        else:
            return "フラグが見つかりませんでした"

    # =========================================================================
    # 統合ソルバー
    # =========================================================================

    async def auto_solve(self, problem: str, data: str = "",
                         category: str = "auto", flag_format: str = None) -> str:
        """問題を自動分類して解決し、フラグのみを返す

        Args:
            problem: 問題文
            data: 問題データ（暗号文、ファイルデータなど）
            category: カテゴリ（auto, crypto, forensics, web, pwn, misc）
            flag_format: カスタムフラグ形式（例: "MYCTF{.*}"）

        Returns:
            フラグのみを返す（見つからない場合はエラーメッセージ）
        """
        # まず問題文からフラグを探す（たまにそのまま含まれている）
        all_text = problem + " " + data
        direct_flags = self.extract_flags(all_text, flag_format)
        if direct_flags:
            return '\n'.join(direct_flags)

        # カテゴリを自動判定
        if category == "auto":
            category = self._classify_problem(problem)

        # カテゴリに応じて解決
        if category == "crypto":
            return self.solve_crypto(data if data else problem)
        elif category == "forensics":
            data_bytes = data.encode() if isinstance(data, str) else data
            return self.solve_forensics(data_bytes)
        elif category == "web":
            return self.solve_web(html=data if data else problem)
        else:
            # 汎用解決（全手法を試行）
            result = self.solve_crypto(data if data else problem)
            if "見つかりませんでした" not in result:
                return result
            return "フラグが見つかりませんでした。問題データを確認してください。"

    def _classify_problem(self, problem: str) -> str:
        """問題文からカテゴリを推定"""
        problem_lower = problem.lower()

        crypto_keywords = ['encrypt', 'decrypt', 'cipher', 'rsa', 'aes', 'base64',
                          'xor', 'caesar', 'rot13', '暗号', 'hash', 'md5', 'sha']
        forensics_keywords = ['file', 'image', 'hidden', 'extract', 'steganography',
                             'pcap', 'memory', 'disk', 'recover', '画像', 'ファイル']
        web_keywords = ['http', 'url', 'website', 'cookie', 'session', 'sql',
                       'injection', 'xss', 'web', 'html', 'javascript']
        pwn_keywords = ['buffer', 'overflow', 'exploit', 'binary', 'rop',
                       'shellcode', 'pwn', 'nc', 'netcat', 'remote']

        for kw in crypto_keywords:
            if kw in problem_lower:
                return "crypto"
        for kw in forensics_keywords:
            if kw in problem_lower:
                return "forensics"
        for kw in web_keywords:
            if kw in problem_lower:
                return "web"
        for kw in pwn_keywords:
            if kw in problem_lower:
                return "pwn"

        return "misc"

    # =========================================================================
    # 特殊デコーダー
    # =========================================================================

    def decode_multi(self, data: str) -> str:
        """複数のエンコーディングを自動検出して全てデコード

        Args:
            data: エンコードされたデータ

        Returns:
            フラグまたはデコード結果
        """
        current = data
        steps = []

        for _ in range(10):  # 最大10回のデコード試行
            decoded = None
            method = None

            # Base64
            try:
                test = base64.b64decode(current).decode('utf-8', errors='ignore')
                if test and self._is_printable(test) and test != current:
                    decoded = test
                    method = "Base64"
            except:
                pass

            # Hex
            if not decoded:
                try:
                    if re.match(r'^[0-9a-fA-F]+$', current) and len(current) % 2 == 0:
                        test = bytes.fromhex(current).decode('utf-8', errors='ignore')
                        if test and self._is_printable(test):
                            decoded = test
                            method = "Hex"
                except:
                    pass

            # URL decode
            if not decoded:
                try:
                    from urllib.parse import unquote
                    test = unquote(current)
                    if test != current:
                        decoded = test
                        method = "URL"
                except:
                    pass

            if decoded:
                current = decoded
                steps.append(method)

                # フラグチェック
                flags = self.extract_flags(current)
                if flags:
                    if self.verbose:
                        return f"デコード手順: {' -> '.join(steps)}\n\n{chr(10).join(flags)}"
                    else:
                        return '\n'.join(flags)
            else:
                break

        # 最終結果でフラグ検索
        flags = self.extract_flags(current)
        if flags:
            return '\n'.join(flags)
        elif self.verbose:
            return f"最終結果: {current[:500]}"
        else:
            return "フラグが見つかりませんでした"

    # =========================================================================
    # ステータス
    # =========================================================================

    async def get_status(self) -> str:
        """ステータスを取得"""
        return """=== CTF Auto-Solver Status ===

✅ フラグ抽出: 20+のCTFプラットフォーム対応
✅ Crypto自動解読: Base64, Hex, ROT13, Caesar, XOR, Binary, Octal
✅ Forensics解析: 文字列抽出、Base64検出
✅ Web問題解析: HTML解析、コメント/スクリプト/hidden input検索
✅ 複合デコード: 多重エンコーディング自動検出

💡 モード:
- verbose=False: フラグのみ出力（CTF競技向け）
- verbose=True: 詳細な解析結果も出力

📌 使い方例:
ctf_solve("問題文", "暗号データ", category="crypto")
ctf_solve("問題文", category="auto")  # 自動分類
"""
