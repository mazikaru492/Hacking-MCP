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


if __name__ == "__main__":
    print("Starting Advanced Recon Scanner MCP server...", file=sys.stderr)
    print("Modules loaded: nmap_scanner, web_scanner, dns_scanner, service_analyzer, ssh_explorer, ctf_toolkit", file=sys.stderr)
    print("Features: Network scanning, Web analysis, DNS investigation, Service security analysis, SSH post-connection investigation, CTF Toolkit", file=sys.stderr)
    mcp.run()