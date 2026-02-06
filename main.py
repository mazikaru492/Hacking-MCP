from mcp.server.fastmcp import FastMCP
import sys
from typing import List, Optional
from datetime import datetime
import os
import tempfile
import shutil
import asyncio

# モジュールのインポート
from modules.nmap_scanner import NmapScanner
from modules.web_scanner import WebScanner
from modules.dns_scanner import DNSScanner
from modules.service_analyzer import ServiceAnalyzer
from modules.ssh_explorer import SSHExplorer
from modules.ctf_toolkit import CTFToolkit
from modules.ctf_intelligence import CTFIntelligence
from modules.ctf_strategy import CTFStrategy
from modules.payload_arsenal import PayloadArsenal
from modules.exploit_dev import ExploitDev
from modules.auto_recon import AutoRecon
from modules.post_exploit import PostExploit
from modules.fuzzer import Fuzzer
from modules.memory_module import MemoryModule
from modules.ctf_solver import CTFSolver
from utils.report_manager import ReportManager

# 統合MCPサーバーの初期化
mcp = FastMCP("hacking-mcp")

# 各スキャナーモジュールのインスタンス化
nmap_scanner = NmapScanner()
web_scanner = WebScanner()
dns_scanner = DNSScanner()
service_analyzer = ServiceAnalyzer()
ssh_explorer = SSHExplorer()
ctf_toolkit = CTFToolkit()
ctf_intelligence = CTFIntelligence()
ctf_strategy = CTFStrategy()
payload_arsenal = PayloadArsenal()
exploit_dev = ExploitDev()
auto_recon = AutoRecon()
post_exploit = PostExploit()
fuzzer = Fuzzer()
memory_module = MemoryModule()
ctf_solver = CTFSolver()

# =============================================================================
# Nmap関連ツール
# =============================================================================

@mcp.tool()
async def nmap_basic_scan(target: str, options: Optional[List[str]] = None) -> str:
    """基本的なnmapスキャンを実行します

    Args:
        target: スキャン対象のホスト/ネットワーク
        options: 追加のnmapオプション（例: ["-sV", "-p80,443"]）
    """
    return await nmap_scanner.basic_scan(target, options)

@mcp.tool()
async def nmap_detailed_scan(target: str, ports: str) -> str:
    """詳細なnmapスキャン（バージョン検出付き）を実行します

    Args:
        target: スキャン対象のホスト/ネットワーク
        ports: スキャン対象のポート（必須）
    """
    return await nmap_scanner.detailed_scan(target, ports)

@mcp.tool()
async def nmap_port_scan(target: str, ports: str) -> str:
    """指定したポートのみをスキャンします

    Args:
        target: スキャン対象のホスト/ネットワーク
        ports: ポート指定（例: "80,443" または "1-1000"）
    """
    return await nmap_scanner.port_scan(target, ports)



# =============================================================================
# Web関連ツール
# =============================================================================

@mcp.tool()
async def web_check_headers(url: str) -> str:
    """WebサイトのHTTPヘッダーを確認します

    Args:
        url: チェック対象のURL
    """
    return await web_scanner.check_headers(url)

@mcp.tool()
async def web_check_security(url: str) -> str:
    """Webサイトのセキュリティヘッダーを確認します

    Args:
        url: チェック対象のURL
    """
    return await web_scanner.check_security_headers(url)

@mcp.tool()
async def web_check_robots(url: str) -> str:
    """robots.txtの内容を確認します

    Args:
        url: チェック対象のURL
    """
    return await web_scanner.check_robots_txt(url)

@mcp.tool()
async def web_basic_info(url: str) -> str:
    """Webサイトの基本情報を取得します（レスポンス時間、ステータス、サーバー情報など）

    Args:
        url: チェック対象のURL
    """
    return await web_scanner.get_basic_info(url)

@mcp.tool()
async def web_technology_detection(url: str) -> str:
    """Webサイトで使用されている技術（CMS、フレームワーク、サーバーなど）を検出します

    Args:
        url: チェック対象のURL
    """
    return await web_scanner.technology_detection(url)

@mcp.tool()
async def web_directory_scan(url: str, wordlist: str = "common") -> str:
    """Webディレクトリ・ファイルスキャンを実行します（gobuster風）

    Args:
        url: チェック対象のURL
        wordlist: 使用するwordlist（"common", "dirs", "files"）
    """
    return await web_scanner.directory_scan(url, wordlist)

@mcp.tool()
async def web_comprehensive_scan(url: str) -> str:
    """包括的Webスキャン（基本情報、技術検出、セキュリティチェック、ファイルスキャン）

    Args:
        url: チェック対象のURL
    """
    return await web_scanner.comprehensive_web_scan(url)

@mcp.tool()
async def web_download_file(url: str, file_path: str) -> str:
    """Webサーバーから指定されたファイル（例: index.html, config.js）をダウンロードし、その内容を表示します。

    Args:
        url: 対象のWebサイトのベースURL
        file_path: ダウンロードしたいファイルのパス (例: 'js/main.js', 'robots.txt')
    """
    return await web_scanner.download_web_file(url, file_path)

# =============================================================================
# DNS関連ツール
# =============================================================================

@mcp.tool()
async def dns_lookup(domain: str, record_type: str = "A") -> str:
    """DNS レコードを検索します

    Args:
        domain: 検索対象のドメイン名
        record_type: レコードタイプ（A, AAAA, MX, NS, TXT, CNAME, SOA）
    """
    return await dns_scanner.dns_lookup(domain, record_type)

@mcp.tool()
async def dns_subdomain_enum(domain: str, wordlist: str = "common") -> str:
    """サブドメイン列挙を実行します

    Args:
        domain: 対象ドメイン名
        wordlist: 使用するwordlist（現在は"common"のみ）
    """
    return await dns_scanner.subdomain_enum(domain, wordlist)

@mcp.tool()
async def dns_reverse_lookup(ip: str) -> str:
    """逆引きDNS（PTRレコード）検索を実行します

    Args:
        ip: 逆引きするIPアドレス
    """
    return await dns_scanner.reverse_dns(ip)

@mcp.tool()
async def dns_comprehensive(domain: str) -> str:
    """包括的DNS調査（全レコードタイプ + サブドメイン列挙）

    Args:
        domain: 調査対象のドメイン名
    """
    return await dns_scanner.dns_comprehensive(domain)

# =============================================================================
# ポートサービス分析ツール
# =============================================================================

@mcp.tool()
async def service_analyze_nmap(nmap_output: str) -> str:
    """nmapの結果を解析してサービスのセキュリティ分析を実行します

    Args:
        nmap_output: nmapスキャンの結果テキスト
    """
    return await service_analyzer.analyze_nmap_results(nmap_output)

@mcp.tool()
async def service_quick_analysis(target: str, port: int) -> str:
    """特定ポートのクイックセキュリティ分析を実行します

    Args:
        target: 対象ホスト
        port: 分析するポート番号
    """
    return await service_analyzer.quick_port_analysis(target, port)





# =============================================================================
# 統合・包括的スキャン機能
# =============================================================================

@mcp.tool()
async def quick_recon(target: str) -> str:
    """クイック偵察：基本的なnmapスキャンとWeb情報取得を実行します

    Args:
        target: スキャン対象（IPアドレス、ドメイン名、URL）
    """
    results = []

    # HTTP/HTTPSのURLが指定された場合はポートスキャンをスキップ
    if target.startswith(('http://', 'https://')):
        results.append("=== WEB-ONLY ANALYSIS (Port scan skipped for HTTP/HTTPS URL) ===")
        web_target = target
    else:
        # 基本的なnmapスキャン
        results.append("=== NETWORK SCAN (Nmap) ===")
        nmap_result = await nmap_scanner.basic_scan(target)
        results.append(nmap_result)

        # nmapの結果をサービス分析
        results.append("\n=== SERVICE ANALYSIS ===")
        service_analysis = await service_analyzer.analyze_nmap_results(nmap_result)
        results.append(service_analysis)

        # WebサイトかどうかチェックしてWeb分析を実行
        if '.' in target and not '/' in target:
            # ドメイン名の場合はHTTPSを試してからHTTP
            web_target = f"https://{target}"
        else:
            web_target = None

    if web_target:
        results.append("\n=== WEB ANALYSIS ===")
        web_result = await web_scanner.get_basic_info(web_target)
        results.append(web_result)

        # 技術検出
        results.append("\n=== TECHNOLOGY DETECTION ===")
        tech_result = await web_scanner.technology_detection(web_target)
        results.append(tech_result)

    return "\n".join(results)

@mcp.tool()
async def comprehensive_recon(target: str) -> str:
    """包括的偵察：DNS、nmap、Web、サービス分析のフルスキャン

    Args:
        target: スキャン対象（ドメイン名推奨）
    """
    results = []
    results.append("=== COMPREHENSIVE RECONNAISSANCE ===")
    results.append(f"Target: {target}")
    results.append("=" * 60)

    # HTTP/HTTPSのURLが指定された場合はポートスキャンをスキップ
    if target.startswith(('http://', 'https://')):
        results.append("\n1. Web-Only Analysis (Port scan skipped for HTTP/HTTPS URL)")
        results.append("-" * 60)
        web_comprehensive = await web_scanner.comprehensive_web_scan(target)
        results.append(web_comprehensive)
    else:
        # 1. DNS包括調査（ドメイン名の場合のみ）
        if '.' in target and not target.replace('.', '').isdigit():
            results.append("\n1. DNS Investigation")
            results.append("-" * 30)
            dns_result = await dns_scanner.dns_comprehensive(target)
            results.append(dns_result)
        else:
            results.append("\n1. DNS Investigation")
            results.append("-" * 30)
            results.append("Skipped: IP address detected, DNS investigation not applicable")

        # 2. ネットワークスキャン（基本版から開始）
        results.append("\n2. Network Scan (Basic)")
        results.append("-" * 30)
        basic_nmap = await nmap_scanner.basic_scan(target)
        results.append(basic_nmap)

        # 3. サービス分析
        results.append("\n3. Service Security Analysis")
        results.append("-" * 30)
        service_analysis = await service_analyzer.analyze_nmap_results(basic_nmap)
        results.append(service_analysis)

        # 4. Web包括分析（HTTPサービスが見つかった場合）
        if any(port in basic_nmap for port in ['80', '443', '8080', '8443']):
            web_target = target
            if not target.startswith(('http://', 'https://')):
                # HTTPSを優先して試行
                web_target = f"https://{target}"

            results.append("\n4. Web Application Analysis")
            results.append("-" * 30)
            web_comprehensive = await web_scanner.comprehensive_web_scan(web_target)
            results.append(web_comprehensive)

    return "\n".join(results)

@mcp.tool()
async def domain_investigation(domain: str) -> str:
    """ドメイン専用調査：DNS、Whois、Web技術、サブドメインの包括調査

    Args:
        domain: 調査対象のドメイン名
    """
    results = []
    results.append("=== DOMAIN INVESTIGATION ===")
    results.append(f"Target Domain: {domain}")
    results.append("=" * 50)

    # 1. DNS包括調査
    results.append("\n1. DNS Records Analysis")
    results.append("-" * 30)
    dns_result = await dns_scanner.dns_comprehensive(domain)
    results.append(dns_result)

    # 2. Web技術検出
    results.append("\n2. Web Technology Stack")
    results.append("-" * 30)
    https_url = f"https://{domain}"
    tech_result = await web_scanner.technology_detection(https_url)
    results.append(tech_result)

    # 3. セキュリティヘッダー分析
    results.append("\n3. Web Security Headers")
    results.append("-" * 30)
    security_result = await web_scanner.check_security_headers(https_url)
    results.append(security_result)

    # 4. 基本的なポートスキャン
    results.append("\n4. Basic Port Scan")
    results.append("-" * 30)
    port_result = await nmap_scanner.basic_scan(domain)
    results.append(port_result)

    return "\n".join(results)

@mcp.tool()
async def web_security_audit(url: str) -> str:
    """Web セキュリティ監査：包括的なWebアプリケーション セキュリティチェック

    Args:
        url: 監査対象のURL
    """
    results = []
    results.append("=== WEB SECURITY AUDIT ===")
    results.append(f"Target: {url}")
    results.append("=" * 50)

    # 1. 基本情報とレスポンス分析
    results.append("\n1. Basic Information & Response Analysis")
    results.append("-" * 45)
    basic_info = await web_scanner.get_basic_info(url)
    results.append(basic_info)

    # 2. セキュリティヘッダー詳細分析
    results.append("\n2. Security Headers Analysis")
    results.append("-" * 35)
    security_headers = await web_scanner.check_security_headers(url)
    results.append(security_headers)

    # 3. 技術スタック検出
    results.append("\n3. Technology Stack Detection")
    results.append("-" * 35)
    tech_detection = await web_scanner.technology_detection(url)
    results.append(tech_detection)

    # 4. 共通ファイル・ディレクトリ検索
    results.append("\n4. Common Files & Directories")
    results.append("-" * 35)
    dir_scan = await web_scanner.directory_scan(url, "common")
    results.append(dir_scan)

    # 5. robots.txt分析
    results.append("\n5. robots.txt Analysis")
    results.append("-" * 25)
    robots_analysis = await web_scanner.check_robots_txt(url)
    results.append(robots_analysis)

    return "\n".join(results)







# =============================================================================
# レポート作成ツール
# =============================================================================

@mcp.tool()
async def comprehensive_recon_with_report(target: str) -> str:
    """包括的偵察を行い、結果をレポートとして保存します"""

    # 1. レポートマネージャーを初期化
    report = ReportManager(target)
    print(f"[*] Starting comprehensive recon with reporting for {target}...")

    # HTTP/HTTPSのURLが指定された場合はポートスキャンをスキップ
    if target.startswith(('http://', 'https://')):
        print(f"[*] HTTP/HTTPS URL detected, skipping port scan for {target}")

        # Web包括分析を実行
        web_comprehensive = await web_scanner.comprehensive_web_scan(target)
        report.add_section("Web Application Analysis", web_comprehensive)

        # スクリーンショットを撮影
        ss_filename = f"{target.replace('://', '_').replace(':', '_').replace('/', '_')}.png"
        ss_path = os.path.join(report.ss_dir, ss_filename)

        if await web_scanner.take_screenshot(target, ss_path):
            report.add_screenshot(target, ss_path)
    else:
        # 2. ネットワークスキャンを実行し、レポートに追記
        # まず基本スキャンで開放ポートを特定
        basic_nmap = await nmap_scanner.basic_scan(target)
        open_ports = nmap_scanner._extract_open_ports_from_result(basic_nmap)

        if open_ports:
            ports_str = ",".join(open_ports)
            detailed_nmap = await nmap_scanner.detailed_scan(target, ports_str)
        else:
            detailed_nmap = basic_nmap

        report.add_section("Nmap Scan Results", detailed_nmap)

        # 3. HTTP/HTTPSサービスがあればスクリーンショットを撮影
        open_ports = nmap_scanner._extract_open_ports_from_result(detailed_nmap)
        web_ports_found = False # Webポートが見つかったかどうかのフラグ

        for port in open_ports:
            # 一般的なWebポートをチェック
            if port in ['80', '443', '8080', '8443']:
                web_ports_found = True
                protocol = "https" if port in ['443', '8443'] else "http"
                # ポート番号を含めたURLを生成
                service_url = f"{protocol}://{target}:{port}"

                ss_filename = f"{service_url.replace('://', '_').replace(':', '_')}.png"
                ss_path = os.path.join(report.ss_dir, ss_filename)

                if await web_scanner.take_screenshot(service_url, ss_path):
                    report.add_screenshot(service_url, ss_path)

        # 4. DNSスキャンを実行し、レポートに追記
        dns_result = await dns_scanner.dns_comprehensive(target)
        report.add_section("DNS Analysis", dns_result)

        # 5. Webポートが見つかった場合のみ、Web包括分析を実行
        if web_ports_found:
            # web_scannerが賢くなったので、ターゲットをそのまま渡すだけで良い
            web_comprehensive = await web_scanner.comprehensive_web_scan(target)
            report.add_section("Web Application Analysis", web_comprehensive)
        else:
            report.add_section("Web Application Analysis", "No open web ports (80, 443, 8080, 8443) found. Skipping web scan.")

    # 6. 最後に短い完了メッセージだけを返す
    final_message = f"✅ Scan complete. Full report saved at: {report.report_path}"
    print(final_message) # 念のためコンテナのログにも出力
    return final_message

# =============================================================================
# SSH接続後調査ツール
# =============================================================================

@mcp.tool()
async def ssh_explore_current_directory(host: str, username: str, password: str, port: int = 22) -> str:
    """SSH接続後のリモートサーバー上の現在のディレクトリを調査します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
    """
    return await ssh_explorer.explore_current_directory(host=host, port=port, username=username, password=password)

@mcp.tool()
async def ssh_search_flag_files(host: str, username: str, password: str, port: int = 22, search_paths: Optional[List[str]] = None) -> str:
    """SSH接続後、リモートサーバー上のflag*.txtやroot.txtファイルを網羅的に検索します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
        search_paths: 検索するパスのリスト（指定しない場合は主要ディレクトリを検索）
    """
    return await ssh_explorer.search_flag_files(host=host, port=port, username=username, password=password, search_paths=search_paths)

@mcp.tool()
async def ssh_explore_system_directories(host: str, username: str, password: str, port: int = 22) -> str:
    """SSH接続後、リモートサーバーのシステムの主要ディレクトリを調査します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
    """
    return await ssh_explorer.explore_system_directories(host=host, port=port, username=username, password=password)

@mcp.tool()
async def ssh_check_hidden_files(host: str, username: str, password: str, port: int = 22, directory: str = '.') -> str:
    """SSH接続後、リモートサーバー上の隠しファイルを検索します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
        directory: 検索するディレクトリ（デフォルト: 現在のディレクトリ）
    """
    return await ssh_explorer.check_hidden_files(host=host, port=port, username=username, password=password, directory=directory)

@mcp.tool()
async def ssh_comprehensive_exploration(host: str, username: str, password: str, port: int = 22) -> str:
    """SSH接続後、リモートサーバー上のflag*.txtやroot.txtファイルを網羅的に検索します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
    """
    return await ssh_explorer.comprehensive_exploration(host=host, port=port, username=username, password=password)





@mcp.tool()
async def ssh_add_root_privilege_escalation(host: str, username: str, password: str, port: int = 22) -> str:
    """cronjob.shにroot権限取得のためのコマンドを追記します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
    """
    return await ssh_explorer.add_root_privilege_escalation(host=host, port=port, username=username, password=password)

@mcp.tool()
async def ssh_cleanup_files(host: str, username: str, password: str, file_pattern: str = "*.txt", port: int = 22) -> str:
    """指定されたパターンのファイルを削除してディレクトリを整理します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        file_pattern: 削除するファイルのパターン（デフォルト: "*.txt"）
        port: SSHポート番号 (デフォルト: 22)
    """
    return await ssh_explorer.cleanup_files(host=host, port=port, username=username, password=password, file_pattern=file_pattern)

@mcp.tool()
async def ssh_list_current_files(host: str, username: str, password: str, port: int = 22) -> str:
    """現在のディレクトリのファイル一覧を表示します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
    """
    return await ssh_explorer.list_current_files(host=host, port=port, username=username, password=password)

@mcp.tool()
async def ssh_keep_only_root_txt(host: str, username: str, password: str, port: int = 22) -> str:
    """root.txt以外のファイルを削除してディレクトリを整理します

    Args:
        host: 接続先ホストのIPアドレスまたはホスト名
        username: SSHユーザー名
        password: SSHパスワード
        port: SSHポート番号 (デフォルト: 22)
    """
    return await ssh_explorer.keep_only_root_txt(host=host, port=port, username=username, password=password)

# =============================================================================
# ステータス・ヘルプ機能
# =============================================================================

@mcp.tool()
async def scanner_status() -> str:
    """スキャナーの状態とバージョン情報を表示します"""
    status = [
        "=== RECON SCANNER STATUS ===",
        "",
        f"Nmap Scanner: {await nmap_scanner.get_status()}",
        f"Web Scanner: {await web_scanner.get_status()}",
        f"DNS Scanner: {await dns_scanner.get_status()}",
        f"Service Analyzer: {await service_analyzer.get_status()}",
        f"SSH Explorer: Available",
        "",
        "=== AVAILABLE TOOL CATEGORIES ===",
        "",
        "🔍 Network Scanning (nmap_*):",
        "  • nmap_basic_scan: 基本ポートスキャン（高速）",
        "  • nmap_detailed_scan: 詳細スキャン（バージョン検出）",
        "  • nmap_port_scan: 指定ポートスキャン",
        "",
        "🌐 Web Application Testing (web_*):",
        "  • web_basic_info: Web基本情報取得",
        "  • web_check_headers: HTTPヘッダー確認",
        "  • web_check_security: セキュリティヘッダー確認",
        "  • web_technology_detection: 技術スタック検出",
        "  • web_directory_scan: ディレクトリ・ファイルスキャン",
        "  • web_comprehensive_scan: 包括的Webスキャン",
        "  • web_security_audit: Webセキュリティ監査",
        "",
        "🔍 DNS Investigation (dns_*):",
        "  • dns_lookup: DNSレコード検索",
        "  • dns_subdomain_enum: サブドメイン列挙",
        "  • dns_reverse_lookup: 逆引きDNS",
        "  • dns_comprehensive: 包括的DNS調査",
        "",
        "🛡️ Service Analysis (service_*):",
        "  • service_analyze_nmap: nmapの結果を分析",
        "  • service_quick_analysis: 特定ポートの分析",
        "",

        "",
        "🚀 Integrated Reconnaissance:",
        "  • quick_recon: クイック偵察（nmap + web基本）",
        "  • comprehensive_recon: 包括的偵察（フルスキャン）",
        "  • domain_investigation: ドメイン専用調査",
        "  • web_security_audit: Webセキュリティ監査",
        "",
        "🔍 SSH Post-Connection Investigation (ssh_*):",
        "  • ssh_explore_current_directory: 現在のディレクトリ調査（テキストファイル内容読み取り付き）",
        "  • ssh_search_flag_files: flag*.txtやroot.txtファイル網羅検索",
        "  • ssh_explore_system_directories: システムディレクトリ調査",
        "  • ssh_check_hidden_files: 隠しファイル検索",
        "  • ssh_comprehensive_exploration: flag*.txtやroot.txtファイル検索",

        "  • ssh_add_root_privilege_escalation: cronjob.shにroot権限取得コマンドを追記",
        "  • ssh_cleanup_files: 指定パターンのファイル削除・整理",
        "  • ssh_list_current_files: 現在ディレクトリのファイル一覧表示",
        "  • ssh_keep_only_root_txt: root.txt以外のファイルを削除・整理",
        "",
        "📊 Utility:",
        "  • scanner_status: この状態表示",
        "",
        "=== USAGE EXAMPLES ===",
        "",
        "Basic scans:",
        "  quick_recon('scanme.nmap.org')",
        "  nmap_basic_scan('127.0.0.1')",
        "  web_check_security('https://example.com')",
        "",
        "Comprehensive analysis:",
        "  comprehensive_recon('example.com')",
        "  domain_investigation('github.com')",
        "  web_security_audit('https://httpbin.org')",
        "",
        "Specific investigations:",
        "  dns_comprehensive('google.com')",
        "  web_technology_detection('https://wordpress.org')",
        "  service_quick_analysis('target.com', 22)"
    ]
    return "\n".join(status)

@mcp.tool()
async def show_wordlists() -> str:
    """利用可能なwordlistとその内容を表示します"""
    result = [
        "=== AVAILABLE WORDLISTS ===",
        "",
        "DNS Subdomain Enumeration:",
        f"  • common: {len(dns_scanner.common_subdomains)} entries",
        f"    Examples: {', '.join(dns_scanner.common_subdomains[:10])}...",
        "",
        "Web Directory/File Scanning:",
        f"  • common: {len(web_scanner.common_dirs + web_scanner.common_files)} entries total",
        f"  • dirs: {len(web_scanner.common_dirs)} directories",
        f"    Examples: {', '.join(web_scanner.common_dirs[:10])}...",
        f"  • files: {len(web_scanner.common_files)} files",
        f"    Examples: {', '.join(web_scanner.common_files[:10])}...",
        "",
        "Usage:",
        "  dns_subdomain_enum('example.com', 'common')",
        "  web_directory_scan('https://example.com', 'dirs')",
        "  web_directory_scan('https://example.com', 'files')"
    ]
    return "\n".join(result)



# =============================================================================
# CTF Toolkit ツール
# =============================================================================

@mcp.tool()
async def ctf_sqlmap(url: str, options: Optional[str] = None) -> str:
    """SQLmapでSQLインジェクション脆弱性をスキャン

    Args:
        url: テスト対象のURL（パラメータ付き、例: http://example.com/page?id=1）
        options: 追加オプション（例: "--dbs", "--tables"）
    """
    return await ctf_toolkit.sqlmap_scan(url, options)

@mcp.tool()
async def ctf_nikto(target: str) -> str:
    """Niktoでwebサーバーの脆弱性をスキャン

    Args:
        target: ターゲットURL（例: http://example.com）
    """
    return await ctf_toolkit.nikto_scan(target)

@mcp.tool()
async def ctf_gobuster(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Gobusterでディレクトリ列挙

    Args:
        url: ターゲットURL
        wordlist: 使用するワードリスト
    """
    return await ctf_toolkit.gobuster_dir(url, wordlist)

@mcp.tool()
async def ctf_wfuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Wfuzzでファジング実行

    Args:
        url: ターゲットURL（FUZZをプレースホルダーとして使用）
        wordlist: 使用するワードリスト
    """
    return await ctf_toolkit.wfuzz_scan(url, wordlist)

@mcp.tool()
async def ctf_whatweb(url: str) -> str:
    """WhatWebでWeb技術を検出

    Args:
        url: ターゲットURL
    """
    return await ctf_toolkit.whatweb_scan(url)

@mcp.tool()
async def ctf_john(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", format_type: Optional[str] = None) -> str:
    """John the Ripperでハッシュを解読

    Args:
        hash_file: ハッシュファイルのパス
        wordlist: 使用するワードリスト
        format_type: ハッシュ形式（例: "md5", "sha256", "raw-md5"）
    """
    return await ctf_toolkit.john_crack(hash_file, wordlist, format_type)

@mcp.tool()
async def ctf_hydra(target: str, service: str, username: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Hydraでブルートフォース攻撃

    Args:
        target: ターゲットホスト
        service: サービス（ssh, ftp, http-post-form等）
        username: ユーザー名
        wordlist: パスワードワードリスト
    """
    return await ctf_toolkit.hydra_attack(target, service, username, wordlist)

@mcp.tool()
async def ctf_binwalk(file_path: str) -> str:
    """Binwalkでファイル内の埋め込みデータを解析・抽出

    Args:
        file_path: 解析対象ファイル
    """
    return await ctf_toolkit.binwalk_extract(file_path)

@mcp.tool()
async def ctf_foremost(file_path: str, output_dir: str = "/tmp/foremost_output") -> str:
    """Foremostでファイル復元

    Args:
        file_path: 解析対象ファイル
        output_dir: 出力ディレクトリ
    """
    return await ctf_toolkit.foremost_recover(file_path, output_dir)

@mcp.tool()
async def ctf_steghide(file_path: str, passphrase: str = "") -> str:
    """Steghideで隠しデータを抽出

    Args:
        file_path: 対象ファイル（JPEG, BMP, WAV, AU）
        passphrase: パスフレーズ（空の場合はパスフレーズなし）
    """
    return await ctf_toolkit.steghide_extract(file_path, passphrase)

@mcp.tool()
async def ctf_exiftool(file_path: str) -> str:
    """ExifToolでメタデータを解析

    Args:
        file_path: 解析対象ファイル
    """
    return await ctf_toolkit.exiftool_analyze(file_path)

@mcp.tool()
async def ctf_strings(file_path: str, min_length: int = 4) -> str:
    """Stringsでファイルから文字列を抽出

    Args:
        file_path: 対象ファイル
        min_length: 最小文字列長
    """
    return await ctf_toolkit.strings_extract(file_path, min_length)

@mcp.tool()
async def ctf_radare2(file_path: str) -> str:
    """Radare2でバイナリ解析

    Args:
        file_path: 解析対象バイナリ
    """
    return await ctf_toolkit.radare2_analyze(file_path)

@mcp.tool()
async def ctf_objdump(file_path: str) -> str:
    """Objdumpで逆アセンブル

    Args:
        file_path: 対象バイナリ
    """
    return await ctf_toolkit.objdump_disasm(file_path)

@mcp.tool()
async def ctf_ltrace(command: str) -> str:
    """Ltraceでライブラリコールをトレース

    Args:
        command: 実行するコマンド
    """
    return await ctf_toolkit.ltrace_run(command)

@mcp.tool()
async def ctf_tshark(pcap_file: str, filter_expr: Optional[str] = None) -> str:
    """Tsharkでパケット解析

    Args:
        pcap_file: PCAPファイルのパス
        filter_expr: 表示フィルタ（例: "http", "tcp.port==80"）
    """
    return await ctf_toolkit.tshark_analyze(pcap_file, filter_expr)

@mcp.tool()
async def ctf_netcat(host: str, port: int, data: Optional[str] = None) -> str:
    """Netcatで接続

    Args:
        host: 接続先ホスト
        port: ポート番号
        data: 送信するデータ
    """
    return await ctf_toolkit.netcat_connect(host, port, data)

@mcp.tool()
async def ctf_openssl_decrypt(file_path: str, cipher: str, password: str) -> str:
    """OpenSSLで復号

    Args:
        file_path: 暗号化されたファイル
        cipher: 暗号方式（例: aes-256-cbc）
        password: パスワード
    """
    return await ctf_toolkit.openssl_decrypt(file_path, cipher, password)

@mcp.tool()
async def ctf_base64_decode(data: str) -> str:
    """Base64デコード

    Args:
        data: Base64エンコードされた文字列
    """
    return await ctf_toolkit.base64_decode(data)

@mcp.tool()
async def ctf_toolkit_status() -> str:
    """CTFツールキットの状態を確認します"""
    return await ctf_toolkit.get_status()


# =============================================================================
# CTF Toolkit 追加ツール
# =============================================================================

@mcp.tool()
async def ctf_zsteg(file_path: str, options: Optional[str] = None) -> str:
    """Zstegでpng/bmpのステガノグラフィを検出

    Args:
        file_path: 解析対象のPNG/BMPファイル
        options: 追加オプション（例: "-a" で全チャンネル解析）
    """
    return await ctf_toolkit.zsteg_analyze(file_path, options)

@mcp.tool()
async def ctf_pngcheck(file_path: str) -> str:
    """PNGCheckでPNGファイルの整合性をチェック

    Args:
        file_path: チェック対象のPNGファイル
    """
    return await ctf_toolkit.pngcheck_analyze(file_path)

@mcp.tool()
async def ctf_xxd(file_path: str, length: int = 256) -> str:
    """xxdでファイルの16進ダンプを取得

    Args:
        file_path: ダンプ対象ファイル
        length: 表示するバイト数（デフォルト: 256）
    """
    return await ctf_toolkit.xxd_dump(file_path, length)

@mcp.tool()
async def ctf_file(file_path: str) -> str:
    """fileコマンドでファイルタイプを識別

    Args:
        file_path: 識別対象ファイル
    """
    return await ctf_toolkit.file_identify(file_path)

@mcp.tool()
async def ctf_fcrackzip(file_path: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """fcrackzipでZIPファイルのパスワードをクラック

    Args:
        file_path: パスワード付きZIPファイル
        wordlist: 使用するワードリスト
    """
    return await ctf_toolkit.fcrackzip_crack(file_path, wordlist)

@mcp.tool()
async def ctf_hashid(hash_string: str) -> str:
    """hashidでハッシュタイプを識別

    Args:
        hash_string: 識別対象のハッシュ文字列
    """
    return await ctf_toolkit.identify_hash(hash_string)

@mcp.tool()
async def ctf_stegseek(file_path: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Stegseekで高速steghideパスワードクラック

    Args:
        file_path: 対象ファイル（JPEG, BMP等）
        wordlist: 使用するワードリスト
    """
    return await ctf_toolkit.stegseek_extract(file_path, wordlist)

@mcp.tool()
async def ctf_pdfparser(file_path: str) -> str:
    """pdf-parserでPDF構造を解析

    Args:
        file_path: 解析対象のPDFファイル
    """
    return await ctf_toolkit.pdfparser_analyze(file_path)


# =============================================================================
# CTF Intelligence ツール（AI支援分析）
# =============================================================================

@mcp.tool()
async def ctf_analyze_crypto(text: str) -> str:
    """暗号テキストを自動分析（Base64, Hex, ROT13, Caesar, ハッシュ識別等）

    Args:
        text: 分析対象の暗号文または文字列
    """
    return await ctf_intelligence.analyze_crypto(text)

@mcp.tool()
async def ctf_analyze_file(file_path: str) -> str:
    """ファイルをフォレンジック分析（マジックバイト、エントロピー、CTFパターン検索）

    Args:
        file_path: 分析対象のファイル
    """
    return await ctf_intelligence.analyze_file(file_path)

@mcp.tool()
async def ctf_analyze_binary(file_path: str) -> str:
    """バイナリのセキュリティ機能を分析（checksec相当：PIE, NX, Canary等）

    Args:
        file_path: 解析対象のELFバイナリ
    """
    return await ctf_intelligence.analyze_binary(file_path)

@mcp.tool()
async def ctf_web_payloads(vuln_type: str) -> str:
    """Web脆弱性のペイロード一覧を取得（sql, xss, ssti, lfi）

    Args:
        vuln_type: 脆弱性タイプ（sql, xss, ssti, lfi）
    """
    return await ctf_intelligence.get_web_payloads(vuln_type)

@mcp.tool()
async def ctf_exploit_strategy(vuln_type: str) -> str:
    """エクスプロイト戦略の提案（bof, format, rop, heap）

    Args:
        vuln_type: 脆弱性タイプ（bof, format, rop, heap）
    """
    return await ctf_intelligence.get_exploit_strategy(vuln_type)

@mcp.tool()
async def ctf_intelligence_status() -> str:
    """CTF Intelligenceモジュールのステータスを確認"""
    return await ctf_intelligence.get_status()


# =============================================================================
# CTF Strategy ツール（戦略アドバイザー）
# =============================================================================

@mcp.tool()
async def ctf_suggest_strategy(problem_description: str) -> str:
    """CTF問題の説明から最適なアプローチを提案

    Args:
        problem_description: 問題文または問題の説明
    """
    return await ctf_strategy.analyze_problem(problem_description)

@mcp.tool()
async def ctf_get_strategy(category: str) -> str:
    """カテゴリ別の解法戦略を取得（crypto, web, pwn, reversing, forensics, misc）

    Args:
        category: CTFカテゴリ
    """
    return await ctf_strategy.get_strategy(category)

@mcp.tool()
async def ctf_get_checklist(checklist_type: str) -> str:
    """調査チェックリストを取得（initial, web, binary, crypto, forensics）

    Args:
        checklist_type: チェックリストのタイプ
    """
    return await ctf_strategy.get_checklist(checklist_type)

@mcp.tool()
async def ctf_categories() -> str:
    """利用可能なCTFカテゴリと概要を表示"""
    return await ctf_strategy.get_all_categories()

@mcp.tool()
async def ctf_strategy_status() -> str:
    """CTF Strategyモジュールのステータスを確認"""
    return await ctf_strategy.get_status()


# =============================================================================
# Payload Arsenal（ペイロードアーセナル）
# =============================================================================

@mcp.tool()
async def get_reverse_shell(shell_type: str, ip: str, port: int) -> str:
    """リバースシェルペイロードを生成

    Args:
        shell_type: シェルタイプ (bash, python, php, perl, nc, powershell等)
        ip: 攻撃者のIPアドレス
        port: リスニングポート
    """
    return payload_arsenal.get_reverse_shell(shell_type, ip, port)

@mcp.tool()
async def get_bind_shell(shell_type: str, port: int) -> str:
    """バインドシェルペイロードを生成

    Args:
        shell_type: シェルタイプ (python, nc, perl等)
        port: バインドするポート
    """
    return payload_arsenal.get_bind_shell(shell_type, port)

@mcp.tool()
async def get_webshell(shell_type: str) -> str:
    """Webシェルを生成

    Args:
        shell_type: シェルタイプ (php, asp, aspx, jsp)
    """
    return payload_arsenal.get_webshell(shell_type)

@mcp.tool()
async def get_msfvenom_payload(payload_type: str, ip: str, port: int,
                                format_type: str = "raw") -> str:
    """msfvenomペイロード生成コマンドを返す

    Args:
        payload_type: タイプ (linux_x64, windows_x64, php等)
        ip: LHOST
        port: LPORT
        format_type: 出力フォーマット
    """
    return payload_arsenal.get_msfvenom_payload(payload_type, ip, port, format_type)

@mcp.tool()
async def get_privesc_payload(privesc_type: str) -> str:
    """権限昇格ペイロードを生成

    Args:
        privesc_type: タイプ (suid_bash, sudo_vi, docker等)
    """
    return payload_arsenal.get_privesc_payload(privesc_type)

@mcp.tool()
async def get_tty_upgrade() -> str:
    """TTYシェルアップグレード方法を返す"""
    return payload_arsenal.get_tty_upgrade()

@mcp.tool()
async def get_file_transfer(method: str) -> str:
    """ファイル転送方法を返す

    Args:
        method: 転送方法 (wget, curl, nc, python, base64等)
    """
    return payload_arsenal.get_file_transfer(method)

@mcp.tool()
async def list_all_payloads() -> str:
    """利用可能な全ペイロードをリスト"""
    return payload_arsenal.list_all_payloads()


# =============================================================================
# Exploit Development（エクスプロイト開発）
# =============================================================================

@mcp.tool()
async def pattern_create(length: int) -> str:
    """サイクリックパターンを生成（BOFオフセット特定用）

    Args:
        length: パターン長
    """
    return exploit_dev.pattern_create(length)

@mcp.tool()
async def pattern_offset(pattern: str, value: str) -> str:
    """パターン内のオフセットを検索

    Args:
        pattern: 生成したパターン
        value: 検索する値（hex or 文字列）
    """
    return exploit_dev.pattern_offset(pattern, value)

@mcp.tool()
async def get_shellcode(shellcode_type: str, format_type: str = "python") -> str:
    """シェルコードを取得

    Args:
        shellcode_type: タイプ (linux_x86_execve, linux_x64_execve等)
        format_type: 出力フォーマット (python, c, hex, raw)
    """
    return exploit_dev.get_shellcode(shellcode_type, format_type)

@mcp.tool()
async def generate_nop_sled(length: int) -> str:
    """NOPスレッドを生成

    Args:
        length: 長さ
    """
    return exploit_dev.generate_nop_sled(length)

@mcp.tool()
async def get_rop_template(arch: str = "x64") -> str:
    """ROPエクスプロイトテンプレートを生成

    Args:
        arch: アーキテクチャ (x86, x64)
    """
    return exploit_dev.get_rop_template(arch)

@mcp.tool()
async def get_format_string_template() -> str:
    """フォーマット文字列エクスプロイトテンプレート"""
    return exploit_dev.get_format_string_template()

@mcp.tool()
async def get_heap_template(technique: str = "tcache") -> str:
    """ヒープエクスプロイトテンプレート

    Args:
        technique: テクニック (tcache, fastbin, house_of_force)
    """
    return exploit_dev.get_heap_template(technique)

@mcp.tool()
async def generate_bof_exploit(offset: int, target_addr: int,
                                arch: str = "x64", shellcode: bool = False) -> str:
    """バッファオーバーフローエクスプロイトを生成

    Args:
        offset: リターンアドレスまでのオフセット
        target_addr: ジャンプ先アドレス
        arch: アーキテクチャ (x86, x64)
        shellcode: シェルコードを含めるか
    """
    return await exploit_dev.generate_bof_exploit(offset, target_addr, arch, shellcode)


# =============================================================================
# Auto Reconnaissance（自動偵察）
# =============================================================================

@mcp.tool()
async def auto_recon_full(target: str) -> str:
    """ターゲットに対する完全自動偵察

    Args:
        target: ターゲットIPまたはホスト名
    """
    return await auto_recon.full_recon(target)

@mcp.tool()
async def auto_recon_web(url: str) -> str:
    """Web専用の詳細偵察

    Args:
        url: ターゲットURL
    """
    return await auto_recon.web_recon(url)

@mcp.tool()
async def suggest_next_action(target: str, current_state: str) -> str:
    """現在の状態から次のアクションを提案

    Args:
        target: ターゲット
        current_state: 現在の状態説明
    """
    return auto_recon.suggest_next_action(target, current_state)


# =============================================================================
# Post-Exploitation（ポストエクスプロイト）
# =============================================================================

@mcp.tool()
async def get_linux_privesc_checks() -> str:
    """Linux権限昇格チェックコマンド一覧"""
    return post_exploit.get_linux_privesc_checks()

@mcp.tool()
async def get_linux_privesc_scripts() -> str:
    """Linux権限昇格自動化スクリプト（LinPEAS等）"""
    return post_exploit.get_linux_privesc_scripts()

@mcp.tool()
async def get_windows_privesc_checks() -> str:
    """Windows権限昇格チェックコマンド一覧"""
    return post_exploit.get_windows_privesc_checks()

@mcp.tool()
async def get_windows_privesc_scripts() -> str:
    """Windows権限昇格自動化スクリプト（WinPEAS等）"""
    return post_exploit.get_windows_privesc_scripts()

@mcp.tool()
async def get_credential_locations(os_type: str = "linux") -> str:
    """クレデンシャル発見場所

    Args:
        os_type: Target OS (linux, windows)
    """
    return post_exploit.get_credential_locations(os_type)

@mcp.tool()
async def get_kernel_exploits(kernel_version: str) -> str:
    """カーネルバージョンから既知のエクスプロイトを提案

    Args:
        kernel_version: カーネルバージョン (例: 5.4.0)
    """
    return post_exploit.get_kernel_exploits(kernel_version)

@mcp.tool()
async def get_persistence_methods(os_type: str = "linux") -> str:
    """永続化手法

    Args:
        os_type: linux or windows
    """
    return post_exploit.get_persistence_methods(os_type)


# =============================================================================
# Fuzzer（ファジング）
# =============================================================================

@mcp.tool()
async def fuzz_pattern_create(length: int) -> str:
    """サイクリックパターンを生成

    Args:
        length: 生成するパターン長
    """
    return fuzzer.generate_pattern(length)

@mcp.tool()
async def fuzz_pattern_offset(pattern: str, value: str) -> str:
    """パターン内のオフセットを検索

    Args:
        pattern: 生成したパターン
        value: 検索値
    """
    return fuzzer.find_pattern_offset(pattern, value)

@mcp.tool()
async def fuzz_generate_bof_payloads(start_len: int = 100, end_len: int = 3000,
                                      step: int = 100) -> str:
    """BOFテスト用ペイロードリストを生成

    Args:
        start_len: 開始長
        end_len: 終了長
        step: 増分
    """
    return fuzzer.generate_bof_payloads(start_len, end_len, step)

@mcp.tool()
async def fuzz_bof_template() -> str:
    """BOFエクスプロイトテンプレート"""
    return fuzzer.get_bof_exploit_template()

@mcp.tool()
async def fuzz_format_string_payloads() -> str:
    """フォーマット文字列脆弱性テスト用ペイロード"""
    return fuzzer.generate_format_string_payloads()

@mcp.tool()
async def fuzz_format_string_template() -> str:
    """フォーマット文字列エクスプロイトテンプレート"""
    return fuzzer.get_format_string_exploit()

@mcp.tool()
async def fuzz_web_payloads(vuln_type: str = "all") -> str:
    """Web脆弱性ファジング用ペイロード

    Args:
        vuln_type: タイプ (sqli, xss, lfi, ssti, cmd, all)
    """
    return fuzzer.generate_web_fuzz_payloads(vuln_type)

@mcp.tool()
async def fuzz_wfuzz_command(url: str, param: str, wordlist: str = "sqli") -> str:
    """wfuzzコマンド生成

    Args:
        url: ターゲットURL
        param: ファジングするパラメータ
        wordlist: ワードリストタイプ
    """
    return await fuzzer.generate_wfuzz_command(url, param, wordlist)


# =============================================================================
# Memory Module（メモリ/学習）
# =============================================================================

@mcp.tool()
async def memory_start_session(target: str, session_type: str = "pentest") -> str:
    """新しい攻撃セッションを開始

    Args:
        target: ターゲット
        session_type: セッションタイプ (pentest, ctf, research)
    """
    return memory_module.start_session(target, session_type)

@mcp.tool()
async def memory_record_action(session_id: str, action: str,
                                result: str, success: bool) -> str:
    """アクションを記録

    Args:
        session_id: セッションID
        action: 実行したアクション
        result: 結果
        success: 成功したか
    """
    return memory_module.record_action(session_id, action, result, success)

@mcp.tool()
async def memory_add_discovery(session_id: str, discovery_type: str,
                                data: str) -> str:
    """発見した情報を記録

    Args:
        session_id: セッションID
        discovery_type: タイプ (port, service, vuln, cred, file)
        data: 発見したデータ
    """
    return memory_module.add_discovery(session_id, discovery_type, data)

@mcp.tool()
async def memory_get_session(session_id: str) -> str:
    """セッションのサマリーを取得

    Args:
        session_id: セッションID
    """
    return memory_module.get_session_summary(session_id)

@mcp.tool()
async def memory_list_sessions() -> str:
    """全セッション一覧"""
    return memory_module.list_sessions()

@mcp.tool()
async def memory_add_knowledge(category: str, key: str, value: str) -> str:
    """知識を追加

    Args:
        category: カテゴリ (service, exploit, technique)
        key: キー
        value: 知識内容
    """
    return memory_module.add_knowledge(category, key, value)

@mcp.tool()
async def memory_search_knowledge(query: str) -> str:
    """知識を検索

    Args:
        query: 検索クエリ
    """
    return memory_module.search_knowledge(query)

@mcp.tool()
async def memory_suggest(service: str, version: str = None) -> str:
    """履歴に基づいて推奨アクションを提案

    Args:
        service: サービス名
        version: バージョン
    """
    return memory_module.suggest_based_on_history(service, version)


# =============================================================================
# 統合ステータス
# =============================================================================

@mcp.tool()
async def autonomous_hacking_status() -> str:
    """自律ハッキングシステムの全モジュールステータス"""
    results = []
    results.append("=== Autonomous Hacking System Status ===\n")

    results.append(await payload_arsenal.get_status())
    results.append(await exploit_dev.get_status())
    results.append(await auto_recon.get_status())
    results.append(await post_exploit.get_status())
    results.append(await fuzzer.get_status())
    results.append(await memory_module.get_status())

    return '\n'.join(results)


# =============================================================================
# CTF Auto-Solver（完全自律CTF問題解決）
# =============================================================================

@mcp.tool()
async def ctf_solve(problem: str, data: str = "", category: str = "auto", flag_format: str = None) -> str:
    """CTF問題を完全自律で解決し、フラグのみを出力

    Args:
        problem: 問題文
        data: 問題データ（暗号文、ファイル内容など）
        category: カテゴリ（auto, crypto, forensics, web, pwn, misc）
        flag_format: カスタムフラグ形式（例: "MYCTF{.*}"）

    Returns:
        フラグのみ
    """
    return await ctf_solver.auto_solve(problem, data, category, flag_format)

@mcp.tool()
def ctf_decode_multi(data: str) -> str:
    """複数のエンコーディングを自動検出して全てデコードし、フラグを抽出

    Args:
        data: エンコードされたデータ

    Returns:
        フラグまたはデコード結果
    """
    return ctf_solver.decode_multi(data)

@mcp.tool()
def ctf_extract_flags(text: str, custom_format: str = None) -> str:
    """テキストからCTFフラグを抽出

    Args:
        text: 検索対象テキスト
        custom_format: カスタムフラグ形式（例: "MYCTF{.*}"）

    Returns:
        見つかったフラグ一覧
    """
    flags = ctf_solver.extract_flags(text, custom_format)
    if flags:
        return '\n'.join(flags)
    return "フラグが見つかりませんでした"

@mcp.tool()
def ctf_solve_crypto(data: str, hint: str = "") -> str:
    """暗号問題を自動解読してフラグを抽出

    Args:
        data: 暗号文
        hint: ヒント（任意）

    Returns:
        フラグまたは解読結果
    """
    return ctf_solver.solve_crypto(data, hint)

@mcp.tool()
async def ctf_solver_status() -> str:
    """CTF Auto-Solverのステータス"""
    return await ctf_solver.get_status()


if __name__ == "__main__":
    print("Starting Autonomous Hacking MCP server...", file=sys.stderr)
    print("Modules loaded: nmap, web, dns, service_analyzer, ssh, ctf_toolkit, ctf_intelligence, ctf_strategy, payload_arsenal, exploit_dev, auto_recon, post_exploit, fuzzer, memory", file=sys.stderr)
    print("Features: Autonomous Reconnaissance, Exploit Development, Post-Exploitation, Fuzzing, Memory/Learning", file=sys.stderr)
    mcp.run()