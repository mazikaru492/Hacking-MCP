FROM python:3.12-bookworm

# 環境変数の設定（インタラクティブモードを無効化）
ENV DEBIAN_FRONTEND=noninteractive

# 基本パッケージとCTFツールのインストール
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # 基本ツール
    nmap \
    dnsutils \
    curl \
    wget \
    sudo \
    bash \
    dos2unix \
    iputils-ping \
    iproute2 \
    net-tools \
    git \
    perl \
    # コンパイル関連
    gcc \
    g++ \
    libxml2-dev \
    libxslt-dev \
    libpcap0.8 \
    libssl-dev \
    # === CTF Web攻撃ツール ===
    sqlmap \
    gobuster \
    dirb \
    # === パスワード解析ツール ===
    john \
    hydra \
    fcrackzip \
    # === フォレンジック・ステガノグラフィ ===
    binwalk \
    foremost \
    steghide \
    libimage-exiftool-perl \
    pngcheck \
    xxd \
    # === リバースエンジニアリング ===
    ltrace \
    strace \
    # === ネットワーク解析 ===
    tcpdump \
    tshark \
    netcat-openbsd \
    # === Ruby for zsteg ===
    ruby \
    ruby-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Niktoのインストール（GitHubから）
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Radare2のインストール（GitHubから）
RUN git clone --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 && \
    cd /tmp/radare2 && \
    sys/install.sh && \
    rm -rf /tmp/radare2

# Zsteg（PNGステガノグラフィ解析）のインストール
RUN gem install zsteg

# Stegseek（高速Steghideクラッカー）のインストール - スキップ（Debian Bookworm互換性問題）
# 代わりにsteghideを使用（既にインストール済み）

# HashID（Pythonツール）のインストール
RUN pip install --no-cache-dir hashid

# pdf-parserのインストール（Didier Stevensツール）
RUN curl -L -o /usr/local/bin/pdf-parser.py https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py && \
    chmod +x /usr/local/bin/pdf-parser.py

# Pwntools/Ropper (エクスプロイト開発用)
RUN pip install --no-cache-dir pwntools ropper

# Wordlistsのダウンロード（rockyou.txt）
RUN mkdir -p /usr/share/wordlists && \
    curl -L -o /usr/share/wordlists/rockyou.txt.gz \
    https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz && \
    gunzip /usr/share/wordlists/rockyou.txt.gz || true

# 共通ワードリストの作成
RUN mkdir -p /usr/share/wordlists/dirb && \
    curl -L -o /usr/share/wordlists/dirb/common.txt \
    https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt

# WFuzz wordlistsのダウンロード
RUN mkdir -p /usr/share/wfuzz/wordlist/Injections && \
    curl -L -o /usr/share/wfuzz/wordlist/Injections/SQL.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt && \
    curl -L -o /usr/share/wfuzz/wordlist/Injections/XSS.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt || true

# 非rootユーザー作成・sudo設定を無効化（root実行に変更）
# RUN useradd -m -s /bin/bash hacker
# RUN echo 'hacker ALL=(ALL) NOPASSWD: /usr/bin/nmap' >> /etc/sudoers ...

# 作業ディレクトリの設定
WORKDIR /app

# 依存関係のコピーとインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwrightのブラウザをインストール
RUN python -m playwright install --with-deps chromium

# アプリケーションファイルのコピー
COPY . .

# scan_resultsディレクトリの作成
RUN mkdir -p scan_results

# レポート保存用のディレクトリを作成し、全ユーザーに書き込み権限を付与
RUN mkdir -p /app/reports && chmod 777 /app/reports

# メモリモジュール用ディレクトリ
RUN mkdir -p /app/memory && chmod 777 /app/memory

# スタートアップスクリプトをコピー
COPY startup.sh .
RUN dos2unix startup.sh && chmod +x startup.sh

# 権限の設定（root実行のため不要だが互換性のため残す場合はコメントアウト）
# RUN chown -R hacker:hacker /app

# 非rootユーザーに切り替え（無効化）
# USER hacker

# スタートアップスクリプトを実行
CMD ["/bin/bash", "./startup.sh"]