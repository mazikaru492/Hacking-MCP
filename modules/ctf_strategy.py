"""
CTF Strategy Module - CTF戦略アドバイザー

問題タイプの分類と解法戦略の提案を行うモジュール:
- 問題タイプ分類器
- 解法戦略データベース
- 調査チェックリスト生成
"""

import re
from typing import List, Dict, Optional


class CTFStrategy:
    """CTF戦略アドバイザー - 問題解決アプローチの提案"""

    # 問題カテゴリのキーワードマッピング
    CATEGORY_KEYWORDS = {
        'crypto': [
            'rsa', 'aes', 'des', 'cipher', 'encrypt', 'decrypt', 'hash', 'md5', 'sha',
            'base64', 'xor', 'caesar', 'vigenere', 'rot13', 'modular', 'prime',
            'public key', 'private key', 'signature', '暗号', '復号', 'ハッシュ'
        ],
        'web': [
            'sql', 'injection', 'xss', 'csrf', 'ssrf', 'lfi', 'rfi', 'cookie',
            'session', 'jwt', 'http', 'request', 'response', 'api', 'authentication',
            'login', 'upload', 'ssti', 'template', 'php', 'python', 'javascript'
        ],
        'pwn': [
            'buffer overflow', 'bof', 'rop', 'shellcode', 'exploit', 'binary',
            'elf', 'heap', 'stack', 'canary', 'aslr', 'pie', 'format string',
            'libc', 'got', 'plt', 'ret2', 'pwntools', 'gdb'
        ],
        'reversing': [
            'reverse', 'disassemble', 'decompile', 'ida', 'ghidra', 'radare',
            'assembly', 'asm', 'x86', 'x64', 'arm', 'mips', 'obfuscate',
            'unpack', 'malware', 'crackme', 'keygen', 'license'
        ],
        'forensics': [
            'forensic', 'memory', 'disk', 'image', 'pcap', 'wireshark', 'volatility',
            'autopsy', 'recover', 'carve', 'hidden', 'steganography', 'stego',
            'exif', 'metadata', 'strings', 'binwalk', 'foremost'
        ],
        'misc': [
            'osint', 'recon', 'trivia', 'quiz', 'puzzle', 'logic', 'network',
            'protocol', 'qr', 'barcode', 'audio', 'video', 'programming'
        ]
    }

    # カテゴリ別解法戦略データベース
    STRATEGY_DATABASE = {
        'crypto': {
            'title': '暗号問題 解法戦略',
            'steps': [
                '1. 暗号文のタイプを特定（Base64, Hex, Binary等）',
                '2. 古典暗号をチェック（Caesar, ROT13, Vigenere等）',
                '3. 現代暗号の場合は脆弱性を探す',
                '4. ハッシュの場合はオンラインクラッカーを試行',
                '5. RSAの場合は公開鍵の脆弱性をチェック',
            ],
            'tools': ['ctf_analyze_crypto', 'ctf_john', 'ctf_base64_decode', 'ctf_openssl_decrypt'],
            'hints': [
                '💡 Base64は必ず == や = で終わるか、長さが4の倍数',
                '💡 Hexは0-9とa-fのみで構成される',
                '💡 RSAでeが小さい場合はHastad攻撃を検討',
                '💡 同じnを使う複数の暗号文があれば共通因数攻撃',
            ]
        },
        'web': {
            'title': 'Web問題 解法戦略',
            'steps': [
                '1. ページのソースコードを確認（コメント、隠しフィールド）',
                '2. robots.txt, .git, backup files をチェック',
                '3. 入力フォームを探しSQLi/XSSを試行',
                '4. Cookie/Sessionの仕組みを分析',
                '5. API endpointを探して調査',
            ],
            'tools': ['ctf_sqlmap', 'ctf_gobuster', 'ctf_nikto', 'web_comprehensive_scan'],
            'hints': [
                '💡 開発者ツールでNetworkタブを必ず確認',
                '💡 ブラウザのCookieを確認して構造を分析',
                '💡 .git露出があれば git-dumper を使用',
                '💡 /admin, /backup, /config 等のパスを試行',
            ]
        },
        'pwn': {
            'title': 'Pwn問題 解法戦略',
            'steps': [
                '1. checksec でセキュリティ機能を確認',
                '2. 脆弱性の特定（BOF, FSB, UAF等）',
                '3. クラッシュオフセットの特定',
                '4. リターンアドレス/GOTのオーバーライト',
                '5. シェル取得またはフラグ読み取り',
            ],
            'tools': ['ctf_analyze_binary', 'ctf_radare2', 'ctf_objdump', 'ctf_strings'],
            'hints': [
                '💡 gets(), strcpy() があればBOFを疑う',
                '💡 printf(user_input) があればFSBを疑う',
                '💡 PIE無効ならROP gadgetが使いやすい',
                '💡 Canary無効ならBOFでリターンアドレス書き換え可能',
            ]
        },
        'reversing': {
            'title': 'リバーシング問題 解法戦略',
            'steps': [
                '1. file コマンドでファイルタイプを確認',
                '2. strings で文字列を抽出',
                '3. IDA/Ghidra でデコンパイル',
                '4. main関数から解析開始',
                '5. 入力検証ロジックを特定',
            ],
            'tools': ['ctf_radare2', 'ctf_objdump', 'ctf_strings', 'ctf_ltrace'],
            'hints': [
                '💡 strcmp, strncmp の引数がフラグの可能性',
                '💡 XOR演算が多い場合は暗号化ロジック',
                '💡 アンパック/難読化解除が必要な場合あり',
                '💡 動的解析(ltrace, strace)で実行フローを確認',
            ]
        },
        'forensics': {
            'title': 'フォレンジック問題 解法戦略',
            'steps': [
                '1. file コマンドでファイルタイプを確認',
                '2. exiftool でメタデータを抽出',
                '3. strings でを隠し文字列をチェック',
                '4. binwalk で埋め込みファイルを抽出',
                '5. ステガノグラフィツールを試行',
            ],
            'tools': ['ctf_analyze_file', 'ctf_exiftool', 'ctf_binwalk', 'ctf_steghide', 'ctf_foremost'],
            'hints': [
                '💡 PNG/JPEGの場合はzsteg, steghideを試行',
                '💡 ファイル末尾に追加データがないか確認',
                '💡 PCAPファイルはWiresharkでプロトコル分析',
                '💡 メモリダンプはVolatilityで解析',
            ]
        },
        'misc': {
            'title': 'Misc問題 解法戦略',
            'steps': [
                '1. 問題文を注意深く読む',
                '2. 添付ファイルのタイプを全て確認',
                '3. OSINTの可能性を検討',
                '4. プログラミング問題の可能性を検討',
                '5. パターン認識（QRコード、モールス等）',
            ],
            'tools': ['ctf_strings', 'ctf_exiftool', 'ctf_analyze_crypto'],
            'hints': [
                '💡 問題文にヒントが隠されていることが多い',
                '💡 ファイル名自体がヒントの場合あり',
                '💡 複数の手法を組み合わせる問題が多い',
                '💡 常識やトリビア知識が求められることも',
            ]
        }
    }

    # 調査チェックリスト
    CHECKLISTS = {
        'initial': [
            '□ 問題文を3回読んだか',
            '□ ファイルタイプを確認したか',
            '□ strings でフラグ形式を検索したか',
            '□ メタデータを確認したか',
            '□ ファイルサイズが怪しくないか',
        ],
        'web': [
            '□ ソースコードのコメントを確認したか',
            '□ robots.txt を確認したか',
            '□ Cookieの内容を確認したか',
            '□ 開発者ツールでネットワークタブを確認したか',
            '□ 隠しフォーム要素を確認したか',
            '□ JavaScript ファイルを確認したか',
            '□ HTTP ヘッダーを確認したか',
        ],
        'binary': [
            '□ checksec で保護機能を確認したか',
            '□ 危険な関数(gets, strcpy等)を使用しているか',
            '□ main関数の引数チェックを確認したか',
            '□ 文字列を抽出してフラグ形式を検索したか',
            '□ デバッガで実行フローを確認したか',
        ],
        'crypto': [
            '□ 暗号文のエンコーディングを特定したか',
            '□ 古典暗号（Caesar, ROT13等）を試行したか',
            '□ 周波数分析を行ったか',
            '□ XOR暗号の可能性を検討したか',
            '□ オンラインハッシュクラッカーを試したか',
        ],
        'forensics': [
            '□ ファイルタイプを確認したか',
            '□ exiftool でメタデータを抽出したか',
            '□ binwalk で埋め込みファイルを探したか',
            '□ ファイル末尾に追加データがないか確認したか',
            '□ ステガノグラフィツールを試行したか',
        ]
    }

    def classify_problem(self, description: str) -> Dict:
        """問題文からカテゴリを推定"""
        description_lower = description.lower()
        scores = {}

        for category, keywords in self.CATEGORY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in description_lower)
            if score > 0:
                scores[category] = score

        if not scores:
            return {
                'category': 'misc',
                'confidence': 'low',
                'reason': 'キーワードが検出されませんでした'
            }

        best_category = max(scores, key=scores.get)
        max_score = scores[best_category]

        confidence = 'high' if max_score >= 3 else 'medium' if max_score >= 2 else 'low'

        return {
            'category': best_category,
            'confidence': confidence,
            'reason': f'{max_score}個のキーワードがマッチ',
            'all_scores': scores
        }

    async def get_strategy(self, category: str) -> str:
        """カテゴリに基づく解法戦略を取得"""
        category = category.lower()
        if category not in self.STRATEGY_DATABASE:
            return f"カテゴリ '{category}' は存在しません。\n利用可能: crypto, web, pwn, reversing, forensics, misc"

        strategy = self.STRATEGY_DATABASE[category]
        result = [f"=== {strategy['title']} ===\n"]

        result.append("📋 解法手順:")
        for step in strategy['steps']:
            result.append(f"  {step}")

        result.append("\n🔧 推奨ツール:")
        for tool in strategy['tools']:
            result.append(f"  - {tool}")

        result.append("\n💡 ヒント:")
        for hint in strategy['hints']:
            result.append(f"  {hint}")

        return "\n".join(result)

    async def get_checklist(self, checklist_type: str) -> str:
        """調査チェックリストを取得"""
        checklist_type = checklist_type.lower()

        if checklist_type not in self.CHECKLISTS:
            return f"チェックリスト '{checklist_type}' は存在しません。\n利用可能: initial, web, binary, crypto, forensics"

        result = [f"=== {checklist_type.upper()} チェックリスト ===\n"]
        for item in self.CHECKLISTS[checklist_type]:
            result.append(item)

        return "\n".join(result)

    async def analyze_problem(self, description: str) -> str:
        """問題を分析し、アプローチを提案"""
        classification = self.classify_problem(description)
        category = classification['category']

        result = ["=== CTF問題分析結果 ===\n"]
        result.append(f"📂 推定カテゴリ: {category.upper()}")
        result.append(f"📊 確信度: {classification['confidence']}")
        result.append(f"📝 理由: {classification['reason']}")

        if 'all_scores' in classification and classification['all_scores']:
            result.append("\n📈 カテゴリスコア:")
            for cat, score in sorted(classification['all_scores'].items(), key=lambda x: x[1], reverse=True):
                result.append(f"  - {cat}: {score}")

        strategy = self.STRATEGY_DATABASE.get(category, self.STRATEGY_DATABASE['misc'])
        result.append(f"\n--- {strategy['title']} ---\n")

        result.append("🚀 推奨アプローチ:")
        for i, step in enumerate(strategy['steps'][:3], 1):
            result.append(f"  {step}")

        result.append("\n🔧 最初に試すべきツール:")
        for tool in strategy['tools'][:3]:
            result.append(f"  - {tool}")

        result.append("\n" + strategy['hints'][0])

        return "\n".join(result)

    async def get_all_categories(self) -> str:
        """利用可能な全カテゴリと概要を表示"""
        result = ["=== CTFカテゴリ一覧 ===\n"]

        categories = {
            'crypto': '暗号解読 - Base64, XOR, RSA, AES等',
            'web': 'Web脆弱性 - SQLi, XSS, SSTI, LFI等',
            'pwn': 'バイナリエクスプロイト - BOF, FSB, ROP等',
            'reversing': 'リバースエンジニアリング - 静的/動的解析',
            'forensics': 'フォレンジック - ファイル解析、ステガノ',
            'misc': 'その他 - OSINT, パズル, プログラミング'
        }

        for cat, desc in categories.items():
            result.append(f"📁 {cat}: {desc}")

        result.append("\n💡 使い方:")
        result.append("  ctf_suggest_strategy('問題文または問題の説明')")
        result.append("  ctf_get_strategy('カテゴリ名')")
        result.append("  ctf_get_checklist('チェックリストタイプ')")

        return "\n".join(result)

    async def get_status(self) -> str:
        """ステータスを取得"""
        return """=== CTF Strategy Module Status ===

✅ 問題分類器: 有効
   - 6カテゴリ対応 (crypto, web, pwn, reversing, forensics, misc)
   - キーワードベース分類

✅ 戦略データベース: 有効
   - 各カテゴリの解法手順
   - 推奨ツール一覧
   - ヒント集

✅ チェックリスト: 有効
   - initial, web, binary, crypto, forensics
"""
