"""
Memory Module - 攻撃セッションの記憶と学習

過去の攻撃結果の保存、成功/失敗パターンの学習、ノウハウの蓄積
研究目的専用 - 許可のないシステムへの使用は違法です
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


class MemoryModule:
    """メモリモジュール - 攻撃セッションの記憶と学習"""

    def __init__(self, memory_dir: str = "/app/memory"):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)

        # メモリファイル
        self.sessions_file = self.memory_dir / "sessions.json"
        self.success_patterns_file = self.memory_dir / "success_patterns.json"
        self.failure_patterns_file = self.memory_dir / "failure_patterns.json"
        self.knowledge_file = self.memory_dir / "knowledge.json"

        # メモリをロード
        self.sessions = self._load_json(self.sessions_file, {})
        self.success_patterns = self._load_json(self.success_patterns_file, [])
        self.failure_patterns = self._load_json(self.failure_patterns_file, [])
        self.knowledge = self._load_json(self.knowledge_file, {})

    def _load_json(self, filepath: Path, default: Any) -> Any:
        """JSONファイルをロード"""
        try:
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return default

    def _save_json(self, filepath: Path, data: Any):
        """JSONファイルを保存"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print(f"[Memory] Save error: {e}")

    # ==========================================================================
    # セッション管理
    # ==========================================================================

    def start_session(self, target: str, session_type: str = "pentest") -> str:
        """新しい攻撃セッションを開始

        Args:
            target: ターゲット (IP/ホスト名/URL)
            session_type: セッションタイプ (pentest, ctf, research)
        """
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        session = {
            'id': session_id,
            'target': target,
            'type': session_type,
            'started': datetime.now().isoformat(),
            'status': 'active',
            'phases': [],
            'discovered': {
                'ports': [],
                'services': [],
                'vulnerabilities': [],
                'credentials': [],
                'files': []
            },
            'actions': [],
            'notes': []
        }

        self.sessions[session_id] = session
        self._save_sessions()

        return f"""=== Session Started ===
Session ID: {session_id}
Target: {target}
Type: {session_type}
Started: {session['started']}

💾 セッションは自動保存されます
📝 記録: record_action, add_discovery, add_note
"""

    def record_action(self, session_id: str, action: str,
                      result: str, success: bool) -> str:
        """アクションを記録

        Args:
            session_id: セッションID
            action: 実行したアクション
            result: 結果
            success: 成功したか
        """
        if session_id not in self.sessions:
            return f"❌ Session not found: {session_id}"

        action_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'result': result[:500],  # 結果は500文字まで
            'success': success
        }

        self.sessions[session_id]['actions'].append(action_entry)

        # 成功/失敗パターンに追加
        pattern = {
            'target_type': self._classify_target(self.sessions[session_id]['target']),
            'action': action,
            'result_summary': result[:200],
            'timestamp': datetime.now().isoformat()
        }

        if success:
            self.success_patterns.append(pattern)
            self._save_json(self.success_patterns_file, self.success_patterns[-100:])
        else:
            self.failure_patterns.append(pattern)
            self._save_json(self.failure_patterns_file, self.failure_patterns[-100:])

        self._save_sessions()

        status = "✅ 成功" if success else "❌ 失敗"
        return f"📝 アクション記録: {action} - {status}"

    def add_discovery(self, session_id: str, discovery_type: str,
                      data: str) -> str:
        """発見した情報を記録

        Args:
            session_id: セッションID
            discovery_type: タイプ (port, service, vulnerability, credential, file)
            data: 発見したデータ
        """
        if session_id not in self.sessions:
            return f"❌ Session not found: {session_id}"

        type_map = {
            'port': 'ports',
            'service': 'services',
            'vulnerability': 'vulnerabilities',
            'vuln': 'vulnerabilities',
            'credential': 'credentials',
            'cred': 'credentials',
            'file': 'files'
        }

        key = type_map.get(discovery_type.lower(), discovery_type)
        if key not in self.sessions[session_id]['discovered']:
            self.sessions[session_id]['discovered'][key] = []

        entry = {
            'data': data,
            'discovered_at': datetime.now().isoformat()
        }
        self.sessions[session_id]['discovered'][key].append(entry)
        self._save_sessions()

        return f"🔍 発見記録: {discovery_type} = {data[:50]}..."

    def add_note(self, session_id: str, note: str) -> str:
        """メモを追加

        Args:
            session_id: セッションID
            note: メモ内容
        """
        if session_id not in self.sessions:
            return f"❌ Session not found: {session_id}"

        note_entry = {
            'content': note,
            'timestamp': datetime.now().isoformat()
        }
        self.sessions[session_id]['notes'].append(note_entry)
        self._save_sessions()

        return f"📝 メモ追加: {note[:30]}..."

    def _save_sessions(self):
        """セッションを保存"""
        self._save_json(self.sessions_file, self.sessions)

    def _classify_target(self, target: str) -> str:
        """ターゲットを分類"""
        if target.endswith('.htb') or 'hackthebox' in target:
            return 'htb'
        elif 'tryhackme' in target:
            return 'thm'
        elif target.startswith('10.') or target.startswith('192.168.'):
            return 'internal'
        else:
            return 'external'

    # ==========================================================================
    # セッション参照
    # ==========================================================================

    def get_session_summary(self, session_id: str) -> str:
        """セッションのサマリーを取得

        Args:
            session_id: セッションID
        """
        if session_id not in self.sessions:
            return f"❌ Session not found: {session_id}"

        session = self.sessions[session_id]
        discovered = session['discovered']

        summary = []
        summary.append(f"=== Session Summary: {session_id} ===")
        summary.append(f"Target: {session['target']}")
        summary.append(f"Type: {session['type']}")
        summary.append(f"Started: {session['started']}")
        summary.append(f"Status: {session['status']}")

        summary.append(f"\n【発見事項】")
        summary.append(f"  Ports: {len(discovered.get('ports', []))}")
        summary.append(f"  Services: {len(discovered.get('services', []))}")
        summary.append(f"  Vulnerabilities: {len(discovered.get('vulnerabilities', []))}")
        summary.append(f"  Credentials: {len(discovered.get('credentials', []))}")
        summary.append(f"  Files: {len(discovered.get('files', []))}")

        summary.append(f"\n【アクション】")
        summary.append(f"  Total: {len(session['actions'])}")
        success_count = sum(1 for a in session['actions'] if a['success'])
        summary.append(f"  Success: {success_count}")
        summary.append(f"  Failed: {len(session['actions']) - success_count}")

        # 最近のアクション
        if session['actions']:
            summary.append(f"\n【最近のアクション (最新5件)】")
            for action in session['actions'][-5:]:
                status = "✅" if action['success'] else "❌"
                summary.append(f"  {status} {action['action']}")

        return '\n'.join(summary)

    def list_sessions(self) -> str:
        """全セッション一覧"""
        if not self.sessions:
            return "📂 保存されたセッションはありません"

        results = ["=== Saved Sessions ===\n"]

        for sid, session in sorted(self.sessions.items(),
                                   key=lambda x: x[1]['started'], reverse=True):
            status = session.get('status', 'unknown')
            status_icon = "🟢" if status == 'active' else "⚪"
            results.append(f"{status_icon} {sid}")
            results.append(f"   Target: {session['target']}")
            results.append(f"   Started: {session['started']}")
            results.append(f"   Actions: {len(session['actions'])}")
            results.append("")

        return '\n'.join(results)

    # ==========================================================================
    # 知識ベース
    # ==========================================================================

    def add_knowledge(self, category: str, key: str, value: str) -> str:
        """知識を追加

        Args:
            category: カテゴリ (service, exploit, technique)
            key: キー (例: "vsftpd_2.3.4")
            value: 知識内容
        """
        if category not in self.knowledge:
            self.knowledge[category] = {}

        self.knowledge[category][key] = {
            'content': value,
            'added': datetime.now().isoformat(),
            'used_count': 0
        }

        self._save_json(self.knowledge_file, self.knowledge)
        return f"🧠 知識追加: [{category}] {key}"

    def get_knowledge(self, category: str, key: str = None) -> str:
        """知識を取得

        Args:
            category: カテ��リ
            key: キー (省略時は全件)
        """
        if category not in self.knowledge:
            return f"❌ Category not found: {category}"

        if key:
            if key in self.knowledge[category]:
                entry = self.knowledge[category][key]
                # 使用カウントを増加
                entry['used_count'] = entry.get('used_count', 0) + 1
                self._save_json(self.knowledge_file, self.knowledge)
                return f"=== Knowledge: {key} ===\n\n{entry['content']}"
            else:
                return f"❌ Key not found: {key}"
        else:
            results = [f"=== Knowledge: {category} ===\n"]
            for k, v in self.knowledge[category].items():
                results.append(f"📖 {k}: {v['content'][:50]}...")
            return '\n'.join(results)

    def search_knowledge(self, query: str) -> str:
        """知識を検索

        Args:
            query: 検索クエリ
        """
        results = [f"=== Knowledge Search: {query} ===\n"]
        found = False

        query_lower = query.lower()
        for category, items in self.knowledge.items():
            for key, entry in items.items():
                if (query_lower in key.lower() or
                    query_lower in entry['content'].lower()):
                    found = True
                    results.append(f"📖 [{category}] {key}")
                    results.append(f"   {entry['content'][:100]}...")
                    results.append("")

        if not found:
            results.append("検索結果なし")

        return '\n'.join(results)

    # ==========================================================================
    # 推奨アクション
    # ==========================================================================

    def suggest_based_on_history(self, service: str, version: str = None) -> str:
        """履歴に基づいて推奨アクションを提案

        Args:
            service: サービス名
            version: バージョン (オプション)
        """
        results = [f"=== Suggestions for {service} {version or ''} ===\n"]

        # 成功パターンから検索
        relevant_success = [
            p for p in self.success_patterns
            if service.lower() in p.get('action', '').lower()
        ]

        if relevant_success:
            results.append("【過去の成功パターン】")
            for pattern in relevant_success[-5:]:
                results.append(f"  ✅ {pattern['action']}")
                results.append(f"     → {pattern['result_summary'][:60]}...")
            results.append("")

        # 失敗パターンから回避すべきアクション
        relevant_failures = [
            p for p in self.failure_patterns
            if service.lower() in p.get('action', '').lower()
        ]

        if relevant_failures:
            results.append("【避けるべきパターン】")
            for pattern in relevant_failures[-3:]:
                results.append(f"  ❌ {pattern['action']}")
            results.append("")

        # 知識ベースから
        if 'service' in self.knowledge:
            service_lower = service.lower()
            for key, entry in self.knowledge['service'].items():
                if service_lower in key.lower():
                    results.append(f"【知識ベース】")
                    results.append(entry['content'])
                    break

        if len(results) == 1:
            results.append("関連する履歴が見つかりませんでした")
            results.append("一般的なアプローチを試してください")

        return '\n'.join(results)

    # ==========================================================================
    # ステータス
    # ==========================================================================

    async def get_status(self) -> str:
        """ステータスを取得"""
        session_count = len(self.sessions)
        active_sessions = sum(1 for s in self.sessions.values()
                             if s.get('status') == 'active')
        success_count = len(self.success_patterns)
        failure_count = len(self.failure_patterns)
        knowledge_count = sum(len(v) for v in self.knowledge.values())

        return f"""=== Memory Module Status ===

📂 Storage: {self.memory_dir}
📊 Sessions: {session_count} (Active: {active_sessions})
✅ Success Patterns: {success_count}
❌ Failure Patterns: {failure_count}
🧠 Knowledge Items: {knowledge_count}
"""

    def clear_memory(self, memory_type: str = "all") -> str:
        """メモリをクリア

        Args:
            memory_type: クリアするタイプ (sessions, patterns, knowledge, all)
        """
        if memory_type in ["sessions", "all"]:
            self.sessions = {}
            self._save_sessions()

        if memory_type in ["patterns", "all"]:
            self.success_patterns = []
            self.failure_patterns = []
            self._save_json(self.success_patterns_file, [])
            self._save_json(self.failure_patterns_file, [])

        if memory_type in ["knowledge", "all"]:
            self.knowledge = {}
            self._save_json(self.knowledge_file, {})

        return f"🗑️ Memory cleared: {memory_type}"
