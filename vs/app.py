from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import json
import os
import datetime
import requests
import shutil
import concurrent.futures
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
import re
import threading
import time
import sys
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for, current_app
sys.path.append(os.path.join(os.getcwd(), 'Web Security'))
from web_security.web_security import login_required, start_user_session
import stat
from flask import session, redirect, url_for, flash
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import paramiko
from flask import Flask, request, jsonify
from flask_cors import CORS
import posixpath
import shlex
import uuid
from collections import deque
import hashlib
import tempfile
from datetime import datetime
from flask import send_file
import pdfkit
import base64
from docxtpl import DocxTemplate
from urllib.parse import quote



app = Flask(__name__)
CORS(app)
app.secret_key = 'recon_vault_security_key'

# ---KALI PC CONFIG ---
#Real PC KALI IP 192.168.100.250 
#Tailscale IP : 100.67.33.44
KALI_IP = "100.67.33.44"
KALI_USER = "kali"
KALI_PASS = "kali"
KALI_ALLOWED_BASE = "/home/kali/ReconVault"


def normalize_kali_path(path_value: str) -> str:
    if not path_value:
        return KALI_ALLOWED_BASE
    normalized = posixpath.normpath(path_value)
    if not normalized.startswith("/"):
        normalized = posixpath.join(KALI_ALLOWED_BASE, normalized)
        normalized = posixpath.normpath(normalized)
    return normalized


def is_allowed_kali_path(path_value: str) -> bool:
    normalized = normalize_kali_path(path_value)
    return normalized == KALI_ALLOWED_BASE or normalized.startswith(KALI_ALLOWED_BASE + "/")


def safe_shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"



# --- DATABASE CONFIGURATION ---
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '' # Default XAMPP is empty
app.config['MYSQL_DB'] = 'reconvault_db'
mysql = MySQL(app)


# --- CONFIGURATION ---
SETTINGS_FILE = 'settings.json'
WSL_WORK_DIR = "/home/hongxuan/ReconVault"
WIN_WSL_BASE = r"\\wsl.localhost\kali-linux\home\hongxuan\ReconVault"
WIN_WSL_PATH = os.path.join(WIN_WSL_BASE, "output")
CFG_PATH = r"\\wsl.localhost\kali-linux\home\hongxuan\ReconVault\reconvault.cfg"
WSL_DICT_DIR = "/home/hongxuan/ReconVault/modules/dictionary"



# Default configuration for settings.json
default_settings = {
    "theme_mode": True,
    "language": "English",
    "notifications": False,
    "auto_scan": False,
    "ssl_verification": True,
    "threat_alerts": True,
    "data_encryption": True,
    "scan_timeout": 300,
    "max_retries": 3,
    "threat_level": "medium",

    # Core scan timeouts
    "subfinder_timeout": 180,
    "amass_timeout": 60,
    "gobuster_timeout": 300,
    "httpx_timeout": 45,
    "nuclei_timeout": 60
}
threat_presets = {
            'low': {
                'subfinder_timeout': 120,
                'amass_timeout': 60,
                'gobuster_timeout': 120,
                'httpx_timeout': 45,
                'nuclei_timeout': 60
            },
            'medium': {
                'subfinder_timeout': 180,
                'amass_timeout': 75,
                'gobuster_timeout': 180,
                'httpx_timeout': 60,
                'nuclei_timeout': 90
            },
            'high': {
                'subfinder_timeout': 240,
                'amass_timeout': 180,
                'gobuster_timeout': 300,
                'httpx_timeout': 90,
                'nuclei_timeout': 120
            }
        }

if not os.path.exists(SETTINGS_FILE):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(default_settings, f, indent=4)



# ---Sandbox---
@app.route('/file-scan')
@login_required
def file_scan_page():
    file_scan_result = session.pop('file_scan_result', None)

    if not file_scan_result:
        flash("No file scan result available.", "warning")
        return redirect(url_for('view_scan'))

    return render_template('fileScan.html', result=file_scan_result)

@app.route('/scan_file', methods=['POST'])
@login_required
def scan_file():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    target = request.form.get('target', '').strip() or request.args.get('target', '').strip()
    uploaded_file = request.files.get('file')

    if not uploaded_file or uploaded_file.filename == '':
        flash("No file selected for malware scan.", "danger")
        return redirect(url_for('view_scan', target=target))

    api_key = get_vt_api_key()
    if not api_key:
        flash("VirusTotal API key not found in reconvault.cfg.", "danger")
        return redirect(url_for('view_scan', target=target))

    try:
        file_bytes = uploaded_file.read()
        if not file_bytes:
            flash("Uploaded file is empty.", "danger")
            return redirect(url_for('view_scan', target=target))

        filename = uploaded_file.filename
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        print(f"[DEBUG] Uploaded filename: {filename}")
        print(f"[DEBUG] Target from form: {target}")
        print(f"[DEBUG] SHA256: {sha256_hash}")

        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        # --- STEP 1: Existing file lookup ---
        vt_lookup_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        lookup_resp = requests.get(vt_lookup_url, headers=headers, timeout=20)

        try:
            lookup_data = lookup_resp.json()
        except Exception:
            lookup_data = {}

        print(f"[DEBUG] VT lookup status: {lookup_resp.status_code}")
        print(f"[DEBUG] VT lookup response: {lookup_data}")

        if lookup_resp.status_code == 200 and 'data' in lookup_data:
            attrs = lookup_data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})

            file_scan_result = {
                "filename": filename,
                "sha256": sha256_hash,
                "vt_link": f"https://www.virustotal.com/gui/file/{sha256_hash}",
                "source": "hash_lookup",
                "status": "completed",
                "type_description": attrs.get('type_description', 'Unknown'),
                "meaningful_name": attrs.get('meaningful_name', filename),
                "reputation": attrs.get('reputation', 0),
                "last_analysis_date": attrs.get('last_analysis_date'),
                "stats": {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0)
                },
                "engine_results": attrs.get('last_analysis_results', {})
            }

            session['file_scan_result'] = file_scan_result
            return redirect(url_for('file_scan_page'))

        # --- STEP 2: Upload if not found ---
        if lookup_resp.status_code == 404:
            upload_url = "https://www.virustotal.com/api/v3/files"

            files = {
                "file": (filename, file_bytes)
            }

            upload_headers = {
                "x-apikey": api_key
            }

            upload_resp = requests.post(upload_url, headers=upload_headers, files=files, timeout=60)

            try:
                upload_data = upload_resp.json()
            except Exception:
                upload_data = {}

            print(f"[DEBUG] VT upload status: {upload_resp.status_code}")
            print(f"[DEBUG] VT upload response: {upload_data}")

            if upload_resp.status_code in (200, 201) and 'data' in upload_data:
                analysis_id = upload_data.get('data', {}).get('id')

                file_scan_result = {
                    "filename": filename,
                    "sha256": sha256_hash,
                    "vt_link": f"https://www.virustotal.com/gui/file-analysis/{analysis_id}" if analysis_id else f"https://www.virustotal.com/gui/file/{sha256_hash}",
                    "source": "uploaded",
                    "status": "processing",
                    "analysis_id": analysis_id,
                    "type_description": "Pending analysis",
                    "meaningful_name": filename,
                    "reputation": 0,
                    "last_analysis_date": None,
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0
                    },
                    "engine_results": {}
                }

                session['file_scan_result'] = file_scan_result
                return redirect(url_for('file_scan_page'))

            error_msg = upload_data.get('error', {}).get('message', 'VirusTotal upload failed.')
            flash(f"VirusTotal upload failed: {error_msg}", "danger")
            return redirect(url_for('view_scan', target=target))

        # --- STEP 3: Other VT errors ---
        error_msg = lookup_data.get('error', {}).get('message', 'Unknown VirusTotal error'  )
        flash(f"VirusTotal lookup failed: {error_msg}", "danger")
        return redirect(url_for('view_scan', target=target))

    except Exception as e:
        print(f"[DEBUG] Malware sandbox error: {e}")
        flash(f"Malware sandbox error: {str(e)}", "danger")
        return redirect(url_for('view_scan', target=target))


# --- 1. REMOTE SCAN API ---
@app.route('/api/v1/remote_scan', methods=['POST'])
def handle_remote_scan():
    # Direct access from request json
    data = request.get_json() or {}
    target = data.get('target')
    
    if not target:
        return jsonify({"status": "error", "message": "No target provided"}), 400

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(
            hostname=KALI_IP, 
            username=KALI_USER, 
            password=KALI_PASS,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
            auth_timeout=15,
            banner_timeout=15
        )
        
        # Hardened command execution with absolute paths
        command = f"bash -l -c 'cd /home/kali/ReconVault/modules && ./osint.sh {target}'"
        stdin, stdout, stderr = ssh.exec_command(command)
        
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        return jsonify({"status": "success", "output": output if output else error})

    except Exception as e:
        return jsonify({"status": "error", "message": f"Hardware Connection Failed: {str(e)}"}), 500
    finally:
        ssh.close()



# --- 2. STREAMING KALI RECON ENGINE ---
# app.py (/stream_kali_recon) WHOLE FUNCTION

@app.route('/stream_kali_recon')
def stream_kali_recon():
    if 'logged_in' not in session:
        return Response("Unauthorized", status=401)

    app_instance = current_app._get_current_object()

    raw_target = request.args.get('target', '')
    target = normalize_to_scan_root(clean_target(raw_target))
    mode = request.args.get('mode', 'full')
    raw_modules = request.args.get('modules', 'osint,subdomains,hosts')
    modules_arg = ",".join(raw_modules) if isinstance(raw_modules, list) else raw_modules
    timeout_arg = request.args.get('timeout')
    if timeout_arg and str(timeout_arg).strip().isdigit():
        scan_limit = int(timeout_arg)
    else:
        # Fallback to configured global scan timeout from settings.json
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                settings_data = json.load(f) or {}
            scan_limit = int(settings_data.get('scan_timeout', 3600))
        except Exception:
            scan_limit = 3600

    dict_file = os.path.basename(request.args.get('dict_file', 'dns_list.txt'))
    if not dict_file.endswith('.txt'):
        dict_file = 'dns_list.txt'

    user_id = session.get('user_id', 'anon')
    unique_folder = f"{user_id}_{target.replace('.', '_')}"
    
    def generate_kali():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            started_at = time.time()
            current_progress = 2

            def emit(log_line, progress=None):
                nonlocal current_progress
                if progress is not None:
                    current_progress = max(0, min(int(progress), 100))
                payload = {"log": log_line, "progress": current_progress}
                return f"data: {json.dumps(payload)}\n\n"

            yield ": heartbeat\n\n"
            yield emit(f"[SCAN] Requested target: {raw_target or '-'}", 2)
            yield emit(f"[TARGET] normalized: {raw_target} -> {target}", 3)
            yield emit(f"[SCAN] Mode={mode} | Modules={modules_arg} | Dict={dict_file} | Limit={scan_limit}s", 4)
            yield emit(f"[SSH] Connecting to Kali at {KALI_USER}@{KALI_IP}...", 5)


            ssh.connect(
                hostname=KALI_IP,
                username=KALI_USER,
                password=KALI_PASS,
                look_for_keys=False,
                allow_agent=False,
                timeout=30,
                auth_timeout=30,
                banner_timeout=30
            )

            transport = ssh.get_transport()
            if transport:
                transport.set_keepalive(10)
                yield emit("[SSH] Transport ready, keepalive=10s", 7)

            yield emit("[SSH] Connection established. Kali hardware engaged.", 8)

            try:
                with open('settings.json', 'r') as f:
                    s = json.load(f) or {}
                subfinder_timeout = int(s.get('subfinder_timeout', 180))
                amass_timeout = int(s.get('amass_timeout', 60))
                gobuster_timeout = int(s.get('gobuster_timeout', 300))
                httpx_timeout = int(s.get('httpx_timeout', 60))
                nuclei_timeout = int(s.get('nuclei_timeout', 90))
            except Exception:
                subfinder_timeout, amass_timeout, gobuster_timeout, httpx_timeout, nuclei_timeout = 180, 60, 300, 60, 90
                yield emit("[CONFIG] settings.json unreadable, using default timeout profile.", 9)

            yield emit(
                f"[CONFIG] Timeouts -> subfinder={subfinder_timeout}s, amass={amass_timeout}s, "
                f"gobuster={gobuster_timeout}s, httpx={httpx_timeout}s, nuclei={nuclei_timeout}s",
                9
            )

            cmd = (
                "export PATH=$PATH:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/kali/.local/bin; "
                f"export SUBFINDER_TIMEOUT={subfinder_timeout} "
                f"AMASS_TIMEOUT={amass_timeout} "
                f"GOBUSTER_TIMEOUT={gobuster_timeout} "
                f"HTTPX_TIMEOUT={httpx_timeout} "
                f"NUCLEI_TIMEOUT={nuclei_timeout}; "
                f"cd /home/kali/ReconVault && "
                f"stdbuf -oL -eL bash reconvault.sh {target} {mode} '{modules_arg}' {unique_folder} {scan_limit} '{dict_file}' 2>&1"
            )

            yield emit(f"[ENGINE] Launching reconvault.sh in /home/kali/ReconVault (job={unique_folder})", 10)
            stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
            last_heartbeat = time.time()
            last_stage = "boot"

            while True:
                if stdout.channel.recv_ready():
                    line = stdout.readline()
                    if not line:
                        break

                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()

                    if clean_line:
                        # If engine already emits [PROGRESS xx%], trust that value first.
                        progress_match = re.search(r"\[PROGRESS\s+(\d{1,3})%\]", clean_line)
                        if progress_match:
                            current_progress = min(int(progress_match.group(1)), 95)

                        if "Starting ReconVault" in clean_line or "ReconVault Engine Starting" in clean_line:
                            current_progress = 10
                            last_stage = "starting"
                        elif "Subdomain" in clean_line:
                            current_progress = 35
                            last_stage = "subdomains"
                        elif "Hosts" in clean_line or "Host" in clean_line:
                            current_progress = 50
                            last_stage = "hosts"
                        elif "Web Analysis" in clean_line or "httpx" in clean_line:
                            current_progress = 65
                            last_stage = "web"
                        elif "Vulnerability" in clean_line or "nuclei" in clean_line:
                            current_progress = 80
                            last_stage = "vulns"
                        elif "Packaging" in clean_line or "Synchronizing" in clean_line:
                            current_progress = 95
                            last_stage = "packaging"

                        current_progress = min(current_progress, 95)
                        yield emit(clean_line, current_progress)
                        last_heartbeat = time.time()
                else:
                    if stdout.channel.exit_status_ready():
                        break

                    now = time.time()
                    if now - last_heartbeat >= 20:
                        elapsed = int(now - started_at)
                        yield emit(
                            f"[ENGINE] Heartbeat: running {elapsed}s | stage={last_stage} | progress={current_progress}%",
                            current_progress
                        )
                        last_heartbeat = now

                    time.sleep(1)

            exit_status = stdout.channel.recv_exit_status()
            yield emit(f"[ENGINE] Remote process finished with exit_status={exit_status}", 95)

            yield emit("[SYSTEM] Synchronizing results via SFTP...", 96)

            sftp = ssh.open_sftp()
            report_data = {}
            file_map = {
                "subdomains": "subdomains.txt",
                "subdomains_all": "subdomains_all.txt",
                "subdomains_live": "subdomains_live.txt",
                "hosts": "hosts_detail.txt",
                "web": "web.txt",
                "osint": "osint.txt",
                "vulnerabilities": "vulns.txt",
                "parameters": "parameters.txt"
            }

            for key, filename in file_map.items():
                try:
                    remote_path = f"/home/kali/ReconVault/output/{unique_folder}/{filename}"
                    with sftp.open(remote_path, "r") as f:
                        report_data[key] = f.read().decode('utf-8', errors='replace').strip()
                    yield emit(f"[SFTP] Collected {filename}", 96)
                except Exception:
                    report_data[key] = "No data captured."
                    yield emit(f"[SFTP] Missing/empty {filename}", 96)

            sftp.close()
            yield emit("[SYSTEM] SFTP sync complete.", 97)

            with app_instance.app_context():
                cur = mysql.connection.cursor()
                sql = "INSERT INTO reports (user_id, target, mode, report_data) VALUES (%s, %s, %s, %s)"

                safe_report = shrink_report_for_db(report_data)
                payload = json.dumps(safe_report)
                yield emit(f"[DB] Saving report to MySQL (payload={len(payload)} bytes)...", 98)

                cur.execute(sql, (user_id, target, mode, payload))
                mysql.connection.commit()
                cur.close()
                yield emit("[DB] Report saved successfully.", 99)

            total_elapsed = int(time.time() - started_at)
            yield emit(f"[DONE] Recon sequence complete in {total_elapsed}s.", 100)

        except Exception as e:
            yield emit(f"[CRITICAL] Hardware Engine Error: {str(e)}", 0)
        finally:
            ssh.close()

    return Response(generate_kali(), mimetype='text/event-stream')

# --- UTILITY FUNCTIONS ---

def load_wsl_config(filepath):
    config = {}
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("export"):
                    try:
                        parts = line.replace("export ", "").strip().split("=", 1)
                        config[parts[0]] = parts[1].strip('"').strip("'")
                    except: 
                        continue
    return config

wsl_keys = load_wsl_config(CFG_PATH)


@app.context_processor
def inject_settings():
    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings = json.load(f)
    except Exception:
        settings = default_settings
    return dict(global_settings=settings)




def get_auth_rules():
    """Loads the minimum requirements from your JSON file."""
    try:
        with open('validation_rules.json', 'r') as f:
            data = json.load(f)
            return data['auth']
    except Exception:
        # Safety fallback if the JSON file is missing
        return {"min_username": 4, "min_password": 8}
    

# --- AUTHENTICATION ---
# --- ADD THIS HELPER AT THE TOP OR IN A NEW FILE ---
def load_validation_rules():
    try:
        with open('validation_rules.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        # Fallback defaults if file is missing
        return {
            "auth": {
                "min_username": 4,
                "max_username": 32,
                "min_password": 8,
                "max_password": 128,
                # Username: start with a letter; then letters/digits/._- only.
                "username_regex": r"^[A-Za-z][A-Za-z0-9._-]{3,31}$",
                # Password complexity toggles.
                "password_require_upper": True,
                "password_require_lower": True,
                "password_require_digit": True,
                "password_require_special": True
            }
        }


def validate_new_credentials(username: str, password: str, confirm, rules: dict):
    username = (username or "").strip()
    password = password or ""
    confirm = confirm if confirm is not None else password

    min_u = int(rules.get("min_username", 4))
    max_u = int(rules.get("max_username", 32))
    min_p = int(rules.get("min_password", 8))
    max_p = int(rules.get("max_password", 128))

    if len(username) < min_u or len(username) > max_u:
        return False, f"Username must be {min_u}-{max_u} characters."

    username_re = rules.get("username_regex") or r"^[A-Za-z][A-Za-z0-9._-]+$"
    if not re.match(username_re, username):
        return False, "Username must start with a letter and contain only letters, numbers, dot (.), underscore (_), or dash (-)."

    if len(password) < min_p or len(password) > max_p:
        return False, f"Password must be {min_p}-{max_p} characters."

    if any(ch.isspace() for ch in password):
        return False, "Password must not contain spaces."

    if confirm != password:
        return False, "Password confirmation does not match."

    def need(flag_key: str) -> bool:
        return bool(rules.get(flag_key, True))

    if need("password_require_lower") and not re.search(r"[a-z]", password):
        return False, "Password must include at least 1 lowercase letter."
    if need("password_require_upper") and not re.search(r"[A-Z]", password):
        return False, "Password must include at least 1 uppercase letter."
    if need("password_require_digit") and not re.search(r"[0-9]", password):
        return False, "Password must include at least 1 number."
    if need("password_require_special") and not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least 1 special character."

    return True, ""





@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # 1. Load Rules from JSON
        rules = load_validation_rules()['auth']
        
        username = request.form.get('username')
        password_candidate = request.form.get('password')
        remember = request.form.get('remember') 

        # --- JSON VALIDATION START ---
        if len(username) < rules['min_username']:
            flash(f"Username must be at least {rules['min_username']} characters.", "danger")
            return redirect(url_for('login'))
            
        if len(password_candidate) < rules['min_password']:
            flash(f"Password must be at least {rules['min_password']} characters.", "danger")
            return redirect(url_for('login'))
        # --- JSON VALIDATION END ---
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, password FROM users WHERE username = %s", [username])
        user = cur.fetchone()
        cur.close()
        
        # Verify credentials
        if user and check_password_hash(user[1], password_candidate):
            # --- START SECURITY LOGIC (Modified to use your central helper) ---
            # This calls the logic in web_security.py to set ID, Username, and Time
            from web_security.web_security import start_user_session
            start_user_session(user[0], username)
            # --- END SECURITY LOGIC ---
            
            if remember:
                session.permanent = True  # Cookie lasts for 30 days
            else:
                session.permanent = False # Cookie expires when browser closes
                
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password. Please try again.", "danger")
            return redirect(url_for('login'))
            
    return render_template('login.html')




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # --- STEP 1: LOAD THE LAWBOOK ---
        rules = load_validation_rules()['auth']
        
        username = request.form.get('username')
        password_raw = request.form.get('password')
        confirm_raw = request.form.get('confirm_password')
        
        print(f">>> [DEBUG] Attempting Register: {username}")
        print(f">>> [DEBUG] JSON Rules: Min User({rules['min_username']}), Min Pass({rules['min_password']})")

        # --- STEP 2: THE BARRIER (IF THIS FAILS, WE STOP) ---
        ok, reason = validate_new_credentials(username, password_raw, confirm_raw, rules)
        if not ok:
            print(f">>> [VALIDATION FAIL] {reason}")
            flash(reason, "danger")
            return redirect(url_for('register'))

        # --- STEP 3: DATABASE INSERT (ONLY IF STEP 2 PASSED) ---
        print(">>> [SUCCESS] Rules passed. Hashing and Saving to MySQL...")
        hashed_password = generate_password_hash(password_raw)
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO users(username, password) VALUES(%s, %s)", (username, hashed_password))
            mysql.connection.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            # --- LOGIC TO SHOW GENERIC INFORMATION ---
            print(f">>> [SQL ERROR] {e}") # This still shows in your Kali terminal
            
            # Check if it's the Duplicate Entry error
            if "1062" in str(e):
                flash("This username is already registered. Please try another.", "danger")
            else:
                flash("A system error occurred. Please try again.", "danger")
                
            return redirect(url_for('register')) 
            # -----------------------------------------
        finally:
            cur.close()
            
    return render_template('register.html')



@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('login'))



@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    try:
        user_id = int(session.get('user_id'))
    except (ValueError, TypeError):
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    WSL_OUTPUT_DIR = "/home/hongxuan/ReconVault/output"

    try:
        cur.execute("SELECT target FROM reports WHERE id = %s AND user_id = %s", (report_id, user_id))
        report = cur.fetchone()

        if report:
            target_domain = report[0]
            target_folder = f"{WSL_OUTPUT_DIR}/{user_id}_{target_domain}"

            # Delete DB record (unchanged)
            cur.execute("DELETE FROM reports WHERE id = %s AND user_id = %s", (report_id, user_id))
            mysql.connection.commit()
            print(f"[SUCCESS] DB Record {report_id} deleted for User {user_id}")

            # Delete from Kali (WSL) (unchanged)
            wsl_cmd = f'wsl -d kali-linux -- bash -c "rm -rf {target_folder}"'
            subprocess.run(wsl_cmd, shell=True, capture_output=True, text=True)
            print(f"[DEBUG] WSL deleted folder: {target_folder}")

            # NEW: Also delete from PC Kali over SSH (does not affect WSL logic)
            try:
                remote_folder = f"/home/kali/ReconVault/output/{user_id}_{target_domain.replace('.', '_')}"
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=KALI_IP,
                    username=KALI_USER,
                    password=KALI_PASS,
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=15,
                    auth_timeout=15,
                    banner_timeout=15
                )
                rm_cmd = f"rm -rf -- {shlex.quote(remote_folder)}"
                ssh.exec_command(rm_cmd, get_pty=True)
                ssh.close()
                print(f"[DEBUG] Kali SSH deleted folder: {remote_folder}")
            except Exception as e:
                print(f"[WARN] Kali SSH delete skipped/failed: {e}")

            flash(f"Report for {target_domain} deleted.", "success")
        else:
            print(f"[AUTH ERROR] No match for Report {report_id} and User {user_id}")
            flash("Report not found or unauthorized.", "danger")

    except Exception as e:
        mysql.connection.rollback()
        print(f"[SYSTEM ERROR] {e}")
        flash(f"Error: {e}", "danger")
    finally:
        cur.close()

    return redirect(url_for('reports_page'))



@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    username = session['username']

    cur = mysql.connection.cursor()

    # Total scans
    cur.execute("SELECT COUNT(*) FROM reports WHERE user_id = %s", [user_id])
    total_scans = cur.fetchone()[0] or 0

    # Active targets
    cur.execute("SELECT COUNT(DISTINCT target) FROM reports WHERE user_id = %s", [user_id])
    active_targets = cur.fetchone()[0] or 0

    # Pull full report rows
    cur.execute(
        "SELECT target, mode, scan_date, report_data FROM reports WHERE user_id = %s ORDER BY scan_date DESC",
        [user_id]
    )
    rows = cur.fetchall()
    cur.close()

    threats_detected = 0
    successful_reports = 0
    fast_count = 0
    full_count = 0

    target_risk_map = {}
    recent_owasp_hits = []

    recent_activities = []

    for row in rows:
        target = row[0]
        mode = (row[1] or "").lower()
        scan_date = row[2]
        report_data_raw = row[3]

        if mode == "fast":
            fast_count += 1
        elif mode == "full":
            full_count += 1

        try:
            data = json.loads(report_data_raw) if report_data_raw else {}
        except Exception:
            data = {}

        vuln_raw = data.get("vulnerabilities", "") or ""
        owasp_hits = set(re.findall(r"\[OWASP:(A\d{2}):2021\]", vuln_raw))

        threats_detected += len(owasp_hits)
        successful_reports += 1

        if target not in target_risk_map:
            target_risk_map[target] = 0
        target_risk_map[target] += len(owasp_hits)

        for hit in sorted(owasp_hits):
            recent_owasp_hits.append({
                "target": target,
                "owasp": hit,
                "time": scan_date.strftime('%Y-%m-%d %H:%M') if scan_date else "N/A"
            })

        if len(recent_activities) < 5:
            # Location detection (no DB schema change):
            # Kali SSH reports include extra keys from your SFTP file_map (subdomains_all/subdomains_live).
            location = "PC Kali (SSH)" if ("subdomains_all" in data or "subdomains_live" in data) else "Local WSL"

            recent_activities.append({
                "target": target,
                "time": scan_date.strftime('%Y-%m-%d %H:%M') if scan_date else "N/A",
                "mode": mode.upper() if mode else "N/A",
                "location": location
            })


    success_rate = "0%"
    if total_scans > 0:
        success_rate = f"{round((successful_reports / total_scans) * 100)}%"

    top_risk_target = "-"
    top_risk_count = 0
    if target_risk_map:
        top_risk_target = max(target_risk_map, key=target_risk_map.get)
        top_risk_count = target_risk_map[top_risk_target]

    recent_owasp_hits = recent_owasp_hits[:6]

    return render_template(
        'index.html',
        username=username,
        total_scans=total_scans,
        active_targets=active_targets,
        threats_detected=threats_detected,
        success_rate=success_rate,
        activities=recent_activities,
        top_risk_target=top_risk_target,
        top_risk_count=top_risk_count,
        recent_owasp_hits=recent_owasp_hits,
        fast_count=fast_count,
        full_count=full_count
    )




# --- 1. UTILITIES ---
# --- 1. UTILITIES ---
def normalize_to_scan_root(host: str) -> str:
    """
    Convert any subdomain input to scan root domain.
    Example:
      eprints.utar.edu.my -> utar.edu.my
      api.example.com     -> example.com
    """
    if not host:
        return ""

    host = host.strip(".")
    parts = host.split(".")

    if len(parts) <= 2:
        return host

    # Common multi-level public suffixes that need 3 labels for root domain
    multi_level_suffixes = {
        "com.my", "edu.my", "gov.my", "org.my", "net.my",
        "com.sg", "com.au", "net.au", "org.au",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "co.jp", "co.kr", "co.in"
    }

    suffix2 = ".".join(parts[-2:])

    # If suffix is multi-level (e.g. edu.my), keep last 3 labels.
    if suffix2 in multi_level_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    # Default root domain = last 2 labels
    return ".".join(parts[-2:])


def clean_target(target):
    if not target:
        return ""

    target = target.strip().lower()
    target = re.sub(r"^https?://", "", target)
    target = re.sub(r"^www\.", "", target)

    # Keep only host, remove path and query
    target = target.split("/")[0].split("?")[0].split("#")[0]

    # Remove port if provided (example.com:8080 -> example.com)
    if ":" in target:
        target = target.split(":")[0]

    # Keep safe host characters only
    target = "".join([c for c in target if c.isalnum() or c in ".-"])
    target = target.encode("ascii", "ignore").decode().strip(" .-")

    # Force scan root domain so brute-force starts correctly
    target = normalize_to_scan_root(target)

    return target




def get_available_dicts():
    """
    Lists .txt wordlist files available in the Kali dictionary folder.
    Returns a list of dicts: [{"filename": "dns_list.txt", "label": "dns_list (5k)"}]
    Falls back to hardcoded defaults if the folder is unreadable.
    """
    defaults = [
        {"filename": "dns_list.txt",         "label": "dns_list (default)"},
        {"filename": "dns_big.txt",          "label": "dns_big (large)"},
    ]
    try:
        result = subprocess.run(
            ["wsl", "ls", WSL_DICT_DIR],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return defaults
 
        files = []
        for fname in sorted(result.stdout.splitlines()):
            fname = fname.strip()
            if not fname.endswith(".txt"):
                continue
            # Get line count for the label
            wc = subprocess.run(
                ["wsl", "wc", "-l", f"{WSL_DICT_DIR}/{fname}"],
                capture_output=True, text=True, timeout=5
            )
            count = wc.stdout.strip().split()[0] if wc.returncode == 0 else "?"
            label = f"{fname.replace('.txt','')} ({count} entries)"
            files.append({"filename": fname, "label": label})
 
        return files if files else defaults
    except Exception:
        return defaults
 
 
# 2. Add this route so the frontend can fetch the list via JS (optional):
 
@app.route('/api/v1/dictionaries')
@login_required
def list_dictionaries():
    return jsonify({"dictionaries": get_available_dicts()})




# --- 1. MAIN VIEW ROUTE ---
@app.route('/scan')
@login_required
def view_scan():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    malware_result = session.pop('malware_result', None)

    report_id = (request.args.get('report_id') or '').strip()
    target = request.args.get('target', '').strip()
    target_norm = normalize_to_scan_root(clean_target(target)) if target else ""
    user_id = session.get('user_id')

    # If a specific report_id is provided, always load that exact report (avoids "latest report wins").
    if report_id.isdigit():
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "SELECT report_data, mode, target FROM reports WHERE user_id = %s AND id = %s LIMIT 1",
                (user_id, int(report_id))
            )
            result = cur.fetchone()
            cur.close()

            if result:
                report_data = json.loads(result[0]) if result[0] else {}
                mode = result[1]
                matched_target = result[2]
                return render_template(
                    "scanTarget.html",
                    target=matched_target or target,
                    report=report_data,
                    mode=mode,
                    kali_host=KALI_IP,
                    kali_user=KALI_USER,
                    malware_result=malware_result
                )
        except Exception as e:
            print(f"[UI ERROR] Failed to fetch report_id={report_id}: {e}")
            # Fall back to target lookup below.

    if not target:
        return render_template(
            "scanTarget.html",
            report=None,
            target=None,
            kali_host=KALI_IP,
            kali_user=KALI_USER,
            malware_result=malware_result
        )

    if session.get('pending_noti') == target:
        session.pop('pending_noti', None)

    try:
        cur = mysql.connection.cursor()
        # Try both the raw target and normalized root-domain target so UI can still
        # load reports when scan engine stores normalized domains (e.g. eprints.utar.edu.my -> utar.edu.my).
        query = (
            "SELECT report_data, mode, target FROM reports "
            "WHERE user_id = %s AND (target = %s OR target = %s) "
            "ORDER BY id DESC LIMIT 1"
        )
        cur.execute(query, (user_id, target, target_norm))
        result = cur.fetchone()
        cur.close()

        if result:
            report_data = json.loads(result[0])
            mode = result[1]
            matched_target = result[2]
            return render_template(
                "scanTarget.html",
                target=matched_target or target,
                report=report_data,
                mode=mode,
                kali_host=KALI_IP,
                kali_user=KALI_USER,
                malware_result=malware_result
            )

        return render_template(
            "scanTarget.html",
            target=target,
            report=None,
            kali_host=KALI_IP,
            kali_user=KALI_USER,
            malware_result=malware_result
        )

    except Exception as e:
        print(f"[UI ERROR] Failed to fetch report for {target}: {e}")
        return render_template(
            "scanTarget.html",
            target=target,
            report=None,
            kali_host=KALI_IP,
            kali_user=KALI_USER,
            malware_result=malware_result
        )

            

# ----------------------------
# Visualization (Per Report)
# ----------------------------
def _rv_clean_nonempty_lines(text_value: str) -> list[str]:
    if not text_value or not isinstance(text_value, str):
        return []
    lines = []
    for raw in text_value.splitlines():
        s = (raw or "").strip()
        if not s:
            continue
        if s.startswith("Skipped") or s.startswith("No data") or s.startswith("Error"):
            continue
        lines.append(s)
    return lines


def _rv_count_subdomain_lines(text_value: str) -> int:
    # Count host-like lines in a subdomain list.
    lines = _rv_clean_nonempty_lines(text_value)
    out = 0
    for s in lines:
        # Skip obvious headers/noise
        if s.startswith("===") or s.startswith("---"):
            continue
        # Keep simple: count anything that looks like a hostname
        if "." in s and " " not in s:
            out += 1
    return out


def _rv_count_live_web_from_web_report(web_text: str) -> int:
    # web.txt includes headers + other sections; count URL lines in LIVE WEB SERVICES block.
    lines = _rv_clean_nonempty_lines(web_text)
    return sum(1 for s in lines if s.startswith("http://") or s.startswith("https://"))


def _rv_parse_owasp_top25_param_distribution(parameters_text: str) -> dict:
    # Extract the "=== OWASP TOP 25 HIGH-RISK PARAMETERS ===" section and count parameter names.
    if not parameters_text or not isinstance(parameters_text, str):
        return {}

    m = re.search(
        r"===\s*OWASP\s*TOP\s*25\s*HIGH-RISK\s*PARAMETERS\s*===\s*([\s\S]*?)(?:\n===|\Z)",
        parameters_text,
        flags=re.IGNORECASE
    )
    if not m:
        return {}

    block = m.group(1) or ""
    counts = {}
    for raw in block.splitlines():
        s = (raw or "").strip()
        if not s:
            continue
        if s.startswith("===") or s.startswith("---"):
            continue
        s = s.lstrip("*-•").strip()
        if not s:
            continue

        # Common formats: "param -> ...", "param: ...", "param ..."
        if "->" in s:
            key = s.split("->", 1)[0].strip()
        elif ":" in s:
            key = s.split(":", 1)[0].strip()
        else:
            key = s.split()[0].strip()

        key = re.sub(r"[^a-zA-Z0-9_.-]", "", key).lower()
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1

    return counts


@app.route('/visualize')
@login_required
def visualize_report():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    report_id = (request.args.get('report_id') or '').strip()
    if not report_id.isdigit():
        flash("Missing or invalid report_id for visualization.", "danger")
        return redirect(url_for('reports_page'))

    user_id = session.get('user_id')
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT id, target, scan_date, mode, report_data FROM reports WHERE user_id = %s AND id = %s LIMIT 1",
        (user_id, int(report_id))
    )
    row = cur.fetchone()
    cur.close()

    if not row:
        flash("Report not found (or you do not have access).", "danger")
        return redirect(url_for('reports_page'))

    rid, target, scan_date, mode, report_data_raw = row
    try:
        report_data = json.loads(report_data_raw) if report_data_raw else {}
    except Exception:
        report_data = {}

    sub_all_text = (report_data.get("subdomains_all") or report_data.get("subdomains") or "").strip()
    sub_live_text = (report_data.get("subdomains_live") or "").strip()
    web_text = (report_data.get("web") or "").strip()
    params_text = (report_data.get("parameters") or "").strip()

    live_dns_count = _rv_count_subdomain_lines(sub_all_text)
    if sub_live_text:
        live_web_count = _rv_count_subdomain_lines(sub_live_text)
    else:
        live_web_count = _rv_count_live_web_from_web_report(web_text)

    param_dist = _rv_parse_owasp_top25_param_distribution(params_text)
    # Keep the pie chart readable: top 8 + Other
    top_items = sorted(param_dist.items(), key=lambda kv: kv[1], reverse=True)
    top_items = top_items[:8]
    top_labels = [k for k, _ in top_items]
    top_values = [v for _, v in top_items]
    other_sum = sum(v for _, v in param_dist.items()) - sum(top_values)
    if other_sum > 0:
        top_labels.append("other")
        top_values.append(other_sum)

    chart_data = {
        "live_dns": live_dns_count,
        "live_web": live_web_count,
        "param_labels": top_labels,
        "param_values": top_values
    }

    return render_template(
        "visualize.html",
        report_id=rid,
        target=target,
        mode=mode,
        date=scan_date.strftime('%Y-%m-%d %H:%M') if scan_date else "N/A",
        report=report_data,
        chart_data=chart_data
    )


# --- 1. RECON TRIGGER (Cleaned) ---
@app.route('/recon', methods=['GET', 'POST']) 
def recon():
    if 'logged_in' not in session: return redirect(url_for('login'))
    
    raw_target = request.form.get('target', '').strip()
    target = clean_target(raw_target)
    scan_mode = request.form.get('scan_mode')
    
    # DO NOT start background_scan_task here. 
    # It causes the "Double Run" and empty results.
    return render_template(
        'scanTarget.html',
        target=target,
        mode=scan_mode,
        kali_host=KALI_IP,
        kali_user=KALI_USER
    )




@app.route('/stream_recon')
def stream_recon():
    if 'logged_in' not in session: 
        return Response("Unauthorized", status=401)

    app_instance = current_app._get_current_object()

    raw_target = request.args.get('target')
    target = normalize_to_scan_root(clean_target(raw_target))   # force root domain
    mode = request.args.get('mode')
    raw_modules = request.args.get('modules', '')
    dict_file   = request.args.get('dict_file', 'dns_list.txt')  


    # Sanitise — only allow filename, no path traversal
    dict_file   = os.path.basename(dict_file)
    if not dict_file.endswith('.txt'):
        dict_file = 'dns_list.txt'

    print(f"[DEBUG] UI Selected: {dict_file}") 

    
    user_id = session['user_id']
    unique_folder = f"{user_id}_{target}"

    def generate():
               # --- A. DYNAMIC TIMEOUT LOADING ---
        try:
            with open('settings.json', 'r') as f:
                user_settings = json.load(f)

            scan_limit = int(user_settings.get('scan_timeout', 300))
            subfinder_timeout = int(user_settings.get('subfinder_timeout', 60))
            amass_timeout = int(user_settings.get('amass_timeout', 60))
            gobuster_timeout = int(user_settings.get('gobuster_timeout', 300))
            httpx_timeout = int(user_settings.get('httpx_timeout', 60))
            nuclei_timeout = int(user_settings.get('nuclei_timeout', 90))
        except Exception:
            scan_limit = 300
            subfinder_timeout = 60
            amass_timeout = 60
            gobuster_timeout = 300
            httpx_timeout = 60
            nuclei_timeout = 90

        modules_arg = ",".join(raw_modules) if isinstance(raw_modules, list) else raw_modules

        yield f"data: {json.dumps({'log': f'[SYSTEM] Engine Engaged for {target}', 'progress': 5})}\n\n"
        yield f"data: {json.dumps({'log': f'[CONFIG] Applying UI Timeout: {scan_limit}s', 'progress': 7})}\n\n"
        yield f"data: {json.dumps({'log': f'[CONFIG] Tool Timeouts -> subfinder:{subfinder_timeout}s amass:{amass_timeout}s gobuster:{gobuster_timeout}s httpx:{httpx_timeout}s nuclei:{nuclei_timeout}s', 'progress': 8})}\n\n"

        # --- B. COMMAND EXECUTION (WSL) ---
        cmd = (
            f"cd {WSL_WORK_DIR} && "
            f"export SUBFINDER_TIMEOUT={subfinder_timeout} "
            f"AMASS_TIMEOUT={amass_timeout} "
            f"GOBUSTER_TIMEOUT={gobuster_timeout} "
            f"HTTPX_TIMEOUT={httpx_timeout} "
            f"NUCLEI_TIMEOUT={nuclei_timeout} && "
            f"stdbuf -oL -eL "
            f"./reconvault.sh {target} {mode} '{modules_arg}' "
            f"{unique_folder} {scan_limit} '{dict_file}'"
        )
        print(f"[DEBUG] Command: {cmd}")  
        
        process_exec = subprocess.Popen(
            ["wsl", "bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        current_progress = 10
        for line in iter(process_exec.stdout.readline, ''):
            if line:
                raw_line = line.strip()
                clean_line = re.sub(r'\x1b\[[0-9;]*m', '', raw_line)
                
                # Dynamic Progress Tracking
                if "ReconVault Engine Starting" in clean_line:
                    current_progress = 5
                elif "Dependency Check" in clean_line:
                    current_progress = 8
                elif "FULL SCAN" in clean_line or "FAST PATH" in clean_line:
                    current_progress = 10

                elif "Running subdomains" in clean_line or "Starting Subdomain" in clean_line:
                    current_progress = 18
                elif "passive enumeration" in clean_line:
                    current_progress = 22
                elif "active enumeration" in clean_line:
                    current_progress = 26
                elif "subdomain scan complete" in clean_line.lower():
                    current_progress = 30

                elif "Running host analysis" in clean_line or "Hosts module" in clean_line:
                    current_progress = 36
                elif "Scanning Ports" in clean_line:
                    current_progress = 42
                elif "host analysis complete" in clean_line.lower():
                    current_progress = 48

                elif "Running web analysis" in clean_line or "Starting Web Analysis" in clean_line:
                    current_progress = 54
                elif "httpx" in clean_line.lower():
                    current_progress = 58
                elif "whatweb" in clean_line.lower():
                    current_progress = 62
                elif "gobuster" in clean_line.lower():
                    current_progress = 66
                elif "web analysis complete" in clean_line.lower():
                    current_progress = 70

                elif "Running parameter mining" in clean_line:
                    current_progress = 74
                elif "historical url" in clean_line.lower():
                    current_progress = 76
                elif "AI prediction" in clean_line:
                    current_progress = 80
                elif "parameter mining complete" in clean_line.lower():
                    current_progress = 82

                elif "Running vulnerability scan" in clean_line:
                    current_progress = 84
                elif "Running Nuclei" in clean_line:
                    current_progress = 86
                elif "SQL Injection" in clean_line or "sqlmap" in clean_line.lower():
                    current_progress = 88
                elif "XSS" in clean_line or "dalfox" in clean_line.lower():
                    current_progress = 89
                elif "SSL/TLS" in clean_line or "testssl" in clean_line.lower():
                    current_progress = 90
                elif "Vulnerability scan complete" in clean_line:
                    current_progress = 92

                elif "Running OSINT" in clean_line:
                    current_progress = 72
                elif "WHOIS" in clean_line:
                    current_progress = 74
                elif "mail hygiene" in clean_line.lower():
                    current_progress = 76
                elif "Enumerating DNS" in clean_line:
                    current_progress = 78
                elif "open redirects" in clean_line.lower():
                    current_progress = 80
                elif "theHarvester" in clean_line:
                    current_progress = 82
                elif "Cloud storage" in clean_line:
                    current_progress = 84
                elif "GitHub repository" in clean_line:
                    current_progress = 86
                elif "certificate transparency" in clean_line.lower():
                    current_progress = 88
                elif "OSINT analysis complete" in clean_line:
                    current_progress = 90

                elif "Packaging all results" in clean_line:
                    current_progress = 94
                elif "Report generated" in clean_line:
                    current_progress = 97
                elif "[SUCCESS] Scan complete" in clean_line:
                    current_progress = 100

                
                print(f"[PROGRESS {current_progress}%] {clean_line}")
                yield f"data: {json.dumps({'log': clean_line, 'progress': current_progress})}\n\n"


        
        process_exec.stdout.close()
        return_code = process_exec.wait()

        if return_code == 0:
            yield f"data: {json.dumps({'log': '[SYSTEM] Script finished. Finalizing report...', 'progress': 90})}\n\n"
        else:
            yield f"data: {json.dumps({'log': f'[ERROR] Script exited with code {return_code}', 'progress': 90})}\n\n"


        # --- C. AGGREGATE RESULTS (READING FROM KALI) ---
        time.sleep(2) 
        report_data = {}
        file_map = {
            "subdomains": "subdomains.txt", 
            "hosts": "hosts_detail.txt",
            "web": "web.txt", 
            "osint": "osint.txt",
            "vulnerabilities": "vulns.txt", 
            "parameters": "parameters.txt"
        }

        for key, filename in file_map.items():        # ← must match the block above
            try:
                path = f"{WSL_WORK_DIR}/output/{unique_folder}/{filename}"
                process = subprocess.run(["wsl", "cat", path], capture_output=True, text=True, encoding='utf-8')
                content = process.stdout.strip().replace('\r\n', '\n').replace('\r', '\n')
                
                if process.returncode == 0 and content:
                    report_data[key] = content
                    print(f"[DEBUG] Successfully read {filename}")
                else:
                    report_data[key] = "No data found."
            except Exception as e:
                report_data[key] = f"Error: {str(e)}"

      # --- D. DATABASE SAVE (THE FINAL FIX) ---
        try:
            with app_instance.app_context():
                cur = mysql.connection.cursor()
                sql = "INSERT INTO reports (user_id, target, mode, report_data) VALUES (%s, %s, %s, %s)"

                safe_report = shrink_report_for_db(report_data)
                payload = json.dumps(safe_report)

                values = (user_id, target, mode, payload)
                cur.execute(sql, values)
                mysql.connection.commit()
                cur.close()

            print(f"[DEBUG] DB Save Success for {target}")
            yield f"data: {json.dumps({'log': '[SYSTEM] Results saved to database.', 'progress': 98})}\n\n"
            yield f"data: {json.dumps({'log': '[DONE] Parallel Recon Complete', 'progress': 100})}\n\n"

        except Exception as e:
            print(f"[DEBUG] DB Save Fail: {e}")
            yield f"data: {json.dumps({'log': f'[ERROR] DB Sync Fail: {str(e)}', 'progress': 98})}\n\n"



        
        except GeneratorExit:
            # ✅ CORRECT: User disconnected - kill subprocess and re-raise
            print(f"[SYSTEM] Client disconnected for {target}. Killing subprocess.")
            if process_exec and process_exec.poll() is None:
                process_exec.kill()
                process_exec.wait()
            raise  # ← Re-raise so generator knows it's done

        finally:
            # ✅ ALWAYS cleanup - called even on GeneratorExit
            if process_exec and process_exec.poll() is None:
                print(f"[CLEANUP] Force-killing process for {target}")
                process_exec.kill()
                process_exec.wait()

    return Response(generate(), mimetype='text/event-stream')



@app.route('/api/stop_kali_scan', methods=['POST'])
@login_required
def stop_kali_scan():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=KALI_IP,
            username=KALI_USER,
            password=KALI_PASS,
            look_for_keys=False,
            allow_agent=False,
            timeout=20,
            auth_timeout=20,
            banner_timeout=20
        )

        # Kill current ReconVault runs on Kali
        kill_cmd = "pkill -f 'bash reconvault.sh' || true"
        stdin, stdout, stderr = ssh.exec_command(kill_cmd)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        error = stderr.read().decode('utf-8', errors='replace').strip()

        return jsonify({
            "ok": True,
            "message": "Remote Kali stop signal sent.",
            "output": output or error or "No output"
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    finally:
        ssh.close()


def calculate_risk_score(severity_counts):
    weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1
    }
    score = sum(severity_counts.get(k, 0) * v for k, v in weights.items())
    return min(score, 100)


def get_risk_rating(score):
    if score >= 70:
        return "Critical"
    elif score >= 45:
        return "High"
    elif score >= 25:
        return "Medium"
    elif score >= 10:
        return "Low"
    return "Informational"


def extract_top_findings(severity_findings, top_n=5):
    ordered = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        for item in severity_findings.get(sev, []):
            ordered.append({
                "severity": sev.title(),
                "title": item[:120],
                "evidence": item[:220]
            })
    return ordered[:top_n]


def count_assets(report_target, subdomains_text):
    subdomains = [
        x.strip() for x in subdomains_text.splitlines()
        if x.strip() and "Skipped" not in x and "No data" not in x and "Error" not in x
    ]
    unique_assets = set([report_target] + subdomains)
    return len(unique_assets), subdomains


def build_business_impact(severity_counts):
    if severity_counts.get("critical", 0) > 0:
        return "The assessment identified critical security exposures that may lead to severe compromise of confidentiality, integrity, or availability if left unresolved."
    elif severity_counts.get("high", 0) > 0:
        return "The assessment identified high-risk findings that may significantly weaken the target’s security posture and should be addressed as a priority."
    elif severity_counts.get("medium", 0) > 0:
        return "The assessment identified medium-risk weaknesses that could contribute to attack chaining or broader exploitation if not remediated."
    elif severity_counts.get("low", 0) > 0:
        return "The assessment identified low-risk weaknesses and hardening opportunities that should be addressed as part of routine security improvement."
    return "No significant vulnerabilities were identified in the collected automated evidence. Continued monitoring and periodic reassessment are recommended."

@app.route('/download/pro-report/<path:filename>', methods=['GET'])
@login_required
def download_pro_report(filename):
    export_dir = os.path.join(app.root_path, "exports")
    file_path = os.path.join(export_dir, filename)

    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": f"File not found: {filename}"}), 404

    ext = os.path.splitext(filename)[1].lower()
    if ext == ".docx":
        mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    elif ext == ".html":
        mime = "text/html"
    else:
        mime = "application/pdf"

    return send_file(
        file_path,
        mimetype=mime,
        as_attachment=True,
        download_name=filename
    )

@app.route('/api/v1/generate_pro_report', methods=['POST'])
@login_required
def generate_pro_report():
    try:

        data = request.get_json() or {}
        target = (data.get('target') or '').strip()
        format_requested = (data.get('format') or 'pdf').strip().lower()
        user_id = session.get('user_id')

        if not target:
            return jsonify({"status": "error", "message": "Target is required."}), 400

        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id, target, mode, scan_date, report_data FROM reports "
            "WHERE user_id = %s AND target = %s ORDER BY id DESC LIMIT 1",
            (user_id, target)
        )
        row = cur.fetchone()
        cur.close()

        if not row:
            return jsonify({"status": "error", "message": f"No report found for {target}."}), 404

        report_id, report_target, report_mode, scan_date, report_data_raw = row

        try:
            report_data = json.loads(report_data_raw) if report_data_raw else {}
        except Exception:
            report_data = {}

        vuln_text = (report_data.get("vulnerabilities") or "").strip()
        subdomains_text = (report_data.get("subdomains") or "").strip()
        web_text = (report_data.get("web") or "").strip()
        hosts_text = (report_data.get("hosts") or "").strip()
        osint_text = (report_data.get("osint") or "").strip()
        params_text = (report_data.get("parameters") or "").strip()
        

        # --- AI paramining extraction from parameters.txt content ---
        ai_paramining_status = "No AI parameter mining status found."
        ai_predicted_count = 0
        ai_predicted_lines = []
        ai_model_used = "N/A"

        # model/debug line if present
        m_model = re.search(r"Debug model:\s*(.+)", params_text, re.I)
        if m_model:
            ai_model_used = m_model.group(1).strip()

        # locate AI section
        m_ai = re.search(r"=== AI-PREDICTED PARAMETERS ===(.*?)(===|\Z)", params_text, re.I | re.S)
        if m_ai:
            ai_block = m_ai.group(1).strip()
            raw_lines = [x.strip() for x in ai_block.splitlines() if x.strip()]

            # status line
            fail_line = next((x for x in raw_lines if "AI prediction failed" in x or "skipped" in x.lower()), None)
            if fail_line:
                ai_paramining_status = fail_line
            else:
                ai_paramining_status = "AI prediction complete"

            # predicted parameter lines: format "param -> vuln | purpose"
            ai_predicted_lines = [
                x for x in raw_lines
                if re.match(r"^[a-zA-Z0-9_.-]+\s*->\s*[^|]+\|\s*.+$", x)
            ]
            ai_predicted_count = len(ai_predicted_lines)

        ai_predicted_preview = ai_predicted_lines[:20]
        ai_predicted_text = "\n".join(ai_predicted_preview) if ai_predicted_preview else "No AI predicted parameter lines."

        # Parse "Collected URLs" and "Collected parameterized URLs" from parameters output
        discovered_urls_count = 0
        discovered_param_urls_count = 0

        m_urls = re.search(r"Collected URLs:\s*(\d+)", params_text, re.I)
        if m_urls:
            discovered_urls_count = int(m_urls.group(1))

        m_param_urls = re.search(r"Collected parameterized URLs:\s*(\d+)", params_text, re.I)
        if m_param_urls:
            discovered_param_urls_count = int(m_param_urls.group(1))

        vuln_lines = [l.strip() for l in vuln_text.splitlines() if l.strip()]

        severity_findings = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for line in vuln_lines:
            lo = line.lower()
            if "[critical]" in lo or "critical" in lo:
                severity_findings["critical"].append(line)
            elif "[high]" in lo or " high " in f" {lo} ":
                severity_findings["high"].append(line)
            elif "[medium]" in lo or " medium " in f" {lo} ":
                severity_findings["medium"].append(line)
            elif "[low]" in lo or " low " in f" {lo} ":
                severity_findings["low"].append(line)
            else:
                severity_findings["info"].append(line)

        severity_counts = {k: len(v) for k, v in severity_findings.items()}

        risk_score = calculate_risk_score(severity_counts)
        risk_rating = get_risk_rating(risk_score)
        top_findings = extract_top_findings(severity_findings, top_n=5)
        asset_count, subdomain_rows = count_assets(report_target, subdomains_text)
        business_impact = build_business_impact(severity_counts)

        # Scope rule: always include root target. If no subdomain, root only.
        if report_target not in subdomain_rows:
            subdomain_rows.insert(0, report_target)
        if not subdomain_rows:
            subdomain_rows = [report_target]

        owasp_codes = sorted(set(re.findall(r"\[OWASP:(A\d{2}):2021\]", vuln_text)))
        owasp_comments_map = {
            "A01": "Broken Access Control: enforce server-side authorization and least privilege.",
            "A02": "Cryptographic Failures: enforce modern TLS and certificate hygiene.",
            "A03": "Injection: use parameterized queries, validation and output encoding.",
            "A04": "Insecure Design: add threat modeling and secure design controls.",
            "A05": "Security Misconfiguration: harden defaults and disable exposed debug paths.",
            "A06": "Vulnerable Components: patch and govern dependencies by CVE tracking.",
            "A07": "Identification/Authentication Failures: strengthen auth and session controls.",
            "A08": "Software/Data Integrity Failures: secure CI/CD and artifact integrity.",
            "A09": "Logging/Monitoring Failures: improve telemetry and incident response readiness.",
            "A10": "SSRF: restrict outbound access and validate target URLs."
        }
        owasp_items = [{"code": c, "comment": owasp_comments_map.get(c, "General OWASP risk detected.")} for c in owasp_codes]

        methodology_steps = [
            "Asset discovery and target expansion.",
            "Service fingerprinting and endpoint analysis.",
            "Automated vulnerability checks and focused probing.",
            "OWASP Top 10 evidence mapping.",
            "Severity triage and remediation planning."
        ]

        modules_used = report_data.get("selected_modules") or [
            "Network Map", "Web Services", "Host Infrastructure", "Vulnerabilities", "OWASP Top 10", "OSINT", "AI Params"
        ]

        scope_items = [f"In-scope asset: {x}" for x in subdomain_rows]

        remediation_plan = []
        if "A01" in owasp_codes:
            remediation_plan.append("Enforce object-level access control checks across endpoints.")
        if "A02" in owasp_codes:
            remediation_plan.append("Harden TLS configuration and remove legacy protocols/ciphers.")
        if "A03" in owasp_codes:
            remediation_plan.append("Apply injection-safe coding practices and strict input handling.")
        if "A05" in owasp_codes:
            remediation_plan.append("Implement secure configuration baselines and continuous checks.")
        if "A06" in owasp_codes:
            remediation_plan.append("Patch vulnerable components and maintain dependency inventory.")
        if "A10" in owasp_codes:
            remediation_plan.append("Restrict outbound network paths to mitigate SSRF abuse.")
        if not remediation_plan:
            remediation_plan.append("No explicit OWASP-mapped findings; continue periodic reassessment.")

        tools_used = []
        raw_all = "\n".join([vuln_text, web_text, hosts_text, osint_text, params_text]).lower()
        for t in ["nuclei", "sqlmap", "dalfox", "tinja", "testssl", "commix", "nomore403", "subzy", "httpx", "gowitness"]:
            if t in raw_all:
                tools_used.append(t)
        if not tools_used:
            tools_used = ["ReconVault internal modules"]

        appendix = {
            "scan_date": str(scan_date),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tools_used": tools_used
        }

        # Parse open ports
        open_ports = []
        for line in hosts_text.splitlines():
            m = re.search(r'(?P<host>[a-zA-Z0-9._-]+).*?(?P<port>\d{1,5})/(?P<proto>tcp|udp).*?(?P<service>[a-zA-Z0-9._-]+)?', line, re.I)
            if m:
                open_ports.append({
                    "host": m.group("host"),
                    "port": m.group("port"),
                    "proto": m.group("proto").lower(),
                    "service": m.group("service") or "unknown"
                })
        if not open_ports:
            open_ports = [{"host": report_target, "port": "-", "proto": "-", "service": "No open port data"}]

        # Parse web services
        web_services = []
        for line in web_text.splitlines():
            v = line.strip()
            if not v or "Skipped" in v:
                continue
            url_match = re.search(r'(https?://[^\s]+)', v, re.I)
            status_match = re.search(r'\b(200|201|301|302|307|308|401|403|404|500)\b', v)
            web_services.append({
                "url": url_match.group(1) if url_match else v[:120],
                "status": status_match.group(1) if status_match else "-",
                "detail": v[:160]
            })
        if not web_services:
            web_services = [{"url": "N/A", "status": "-", "detail": "No web service data"}]

        # URL discovery + parameter mining extraction
        discovered_urls_count = 0
        discovered_param_urls_count = 0
        historical_urls_preview = []
        ai_paramining_status = "No AI parameter mining status found."

        m_urls = re.search(r"Collected URLs:\s*(\d+)", params_text, re.I)
        if m_urls:
            discovered_urls_count = int(m_urls.group(1))

        m_param_urls = re.search(r"Collected parameterized URLs:\s*(\d+)", params_text, re.I)
        if m_param_urls:
            discovered_param_urls_count = int(m_param_urls.group(1))

        hist_block = re.search(r"=== FULL URLS WITH PARAMETERS \(top 50\) ===(.*?)(===|\Z)", params_text, re.I | re.S)
        if hist_block:
            lines = [x.strip() for x in hist_block.group(1).splitlines() if x.strip()]
            historical_urls_preview = lines[:20]

        ai_block = re.search(r"=== AI-PREDICTED PARAMETERS ===(.*?)(===|\Z)", params_text, re.I | re.S)
        if ai_block:
            ai_lines = [x.strip() for x in ai_block.group(1).splitlines() if x.strip()]
            if ai_lines:
                ai_paramining_status = ai_lines[0]

        # Attack surface summary
        attack_surface_summary = {
            "assets": len(subdomain_rows),
            "open_ports": len([p for p in open_ports if p.get("port") not in ["-", "", None]]),
            "web_endpoints": len(web_services),
            "historical_urls": discovered_urls_count,
            "parameterized_urls": discovered_param_urls_count
        }

        exec_summary = (
            f"{report_target} was assessed in {str(report_mode).upper()} mode. "
            f"Risk rating is {risk_rating} ({risk_score}/100) with "
            f"{severity_counts['critical']} critical, {severity_counts['high']} high, "
            f"{severity_counts['medium']} medium, and {severity_counts['low']} low findings."
        )

        # Optional logo (base64 data URI for PDF template)
        logo_data_uri = ""
        try:
            logo_path = os.path.join(app.root_path, "static", "img", "logo.png")
            if os.path.exists(logo_path):
                with open(logo_path, "rb") as f:
                    logo_data_uri = "data:image/png;base64," + base64.b64encode(f.read()).decode("utf-8")
        except Exception:
            logo_data_uri = ""

        export_dir = os.path.join(app.root_path, "exports")
        os.makedirs(export_dir, exist_ok=True)
        safe_target = re.sub(r'[^a-zA-Z0-9._-]', '_', report_target.strip())
        date_str = datetime.now().strftime("%Y%m%d")
        base_name = f"ReconVault_{safe_target}_penetrationTestingReport_{report_id}_{date_str}"


        base_context = {
            "system_name": "ReconVault",
            "logo_data_uri": logo_data_uri,
            "report_id": report_id,
            "target": report_target,
            "mode": report_mode,
            "scan_date": scan_date,
            "generated_at": appendix["generated_at"],
            "report_user": session.get("username") or session.get("user") or "Unknown User",
            "scan_type": str(report_mode).upper(),
            "discovered_urls_count": discovered_urls_count,
            "discovered_param_urls_count": discovered_param_urls_count,
            "ai_paramining_status": ai_paramining_status,
            "ai_predicted_count": ai_predicted_count,
            "ai_predicted_preview": ai_predicted_preview,
            "ai_predicted_text": ai_predicted_text,
            "ai_model_used": ai_model_used,



            "exec_summary": exec_summary,
            "business_impact": business_impact,

            "risk_score": risk_score,
            "risk_rating": risk_rating,
            "asset_count": asset_count,

            "scope_items": scope_items,
            "methodology_steps": methodology_steps,
            "modules_used": modules_used,

            "severity_counts": severity_counts,
            "severity_findings": severity_findings,
            "top_findings": top_findings,

            "owasp_items": owasp_items,
            "remediation_plan": remediation_plan,

            "subdomain_rows": subdomain_rows,
            "open_ports": open_ports,
            "web_services": web_services,

            "attack_surface_summary": attack_surface_summary,
            "discovered_urls_count": discovered_urls_count,
            "discovered_param_urls_count": discovered_param_urls_count,
            "historical_urls_preview": historical_urls_preview,
            "ai_paramining_status": ai_paramining_status,

            "tools_used": ", ".join(tools_used),
            "appendix": appendix,
            "report": report_data
        }

        if format_requested == "docx":
            template_path = os.path.join(app.root_path, "templates", "ReconVault_Pro_Template.docx")
            if not os.path.exists(template_path):
                return jsonify({"status": "error", "message": "Word template not found: templates/ReconVault_Pro_Template.docx"}), 500

            filename = f"{base_name}.docx"
            output_path = os.path.join(export_dir, filename)

            tpl = DocxTemplate(template_path)
            tpl.render(base_context)
            tpl.save(output_path)

            return jsonify({
                "status": "success",
                "message": "Professional Word report generated.",
                "download_url": url_for('download_pro_report', filename=filename)
            })
        

        # Generate HTML 
        if format_requested == "html":
            filename = f"{base_name}.html"
            html_path = os.path.join(export_dir, filename)

            html = render_template("pro_report_pdf.html", **base_context)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)

            return jsonify({
                "status": "success",
                "message": "Professional HTML report generated.",
                "download_url": url_for('download_pro_report', filename=filename)
            })

        # Generate PDF Part
        html = render_template("pro_report_pdf.html", **base_context)
        filename = f"{base_name}.pdf"
        pdf_path = os.path.join(export_dir, filename)

        config = pdfkit.configuration(wkhtmltopdf=r"D:\wkhtmltopdf\bin\wkhtmltopdf.exe")
        options = {
            "page-size": "A4",
            "margin-top": "15mm",
            "margin-right": "12mm",
            "margin-bottom": "15mm",
            "margin-left": "12mm",
            "encoding": "UTF-8",
            "enable-local-file-access": None,
            "quiet": ""
        }

        pdfkit.from_string(html, pdf_path, configuration=config, options=options)

        return jsonify({
            "status": "success",
            "message": "Professional PDF report generated.",
            "download_url": url_for('download_pro_report', filename=filename)
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


 # --- 1. REPORTS PAGE (Access Control: Only see your own) ---
@app.route("/reports")
@login_required
def reports_page():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cur = mysql.connection.cursor()

    query = "SELECT id, target, scan_date, mode, report_data FROM reports WHERE user_id = %s ORDER BY scan_date DESC"
    cur.execute(query, [user_id])

    history = []
    for row in cur.fetchall():
        try:
            data = json.loads(row[4]) if row[4] else {}

            sub_raw = data.get('subdomains_all') or data.get('subdomains', "")
            sub_count = len([line for line in sub_raw.strip().split('\n') if line.strip()]) if sub_raw and isinstance(sub_raw, str) else 0

            host_raw = data.get('hosts', "")
            host_raw = data.get('hosts', "")
            asset_count = len([line for line in host_raw.strip().split('\n') if line.strip()]) if host_raw and isinstance(host_raw, str) else 0

            vuln_raw = data.get('vulnerabilities', "")
            vuln_count = len([line for line in vuln_raw.strip().split('\n') if line.strip()]) if vuln_raw and isinstance(vuln_raw, str) else 0

            # Location detection (no DB schema change):
            # Kali SSH reports typically include subdomains_all/subdomains_live from your SFTP file_map.
            location = "PC Kali (SSH)" if ("subdomains_all" in data or "subdomains_live" in data) else "Local WSL"

        except Exception as e:
            print(f"Error parsing: {e}")
            sub_count = asset_count = vuln_count = 0
            location = "Unknown"

        history.append({
            "id": row[0],
            "target": row[1],
            "date": row[2].strftime('%Y-%m-%d %H:%M') if row[2] else "N/A",
            "mode": row[3],
            "location": location,
            "subdomains": sub_count,
            "assets": asset_count,
            "vulns": vuln_count
        })

    cur.close()
    return render_template("report.html", history=history)



@app.route('/delete_all_reports', methods=['POST'])
def delete_all_reports():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    user_id = str(session.get('user_id')).strip()
    if not user_id.isdigit():
        flash("Invalid session. Please log in again.", "danger")
        return redirect(url_for('login'))

    purge_location = (request.form.get("purge_location") or "wsl").strip().lower()
    if purge_location not in ("wsl", "kali", "both"):
        purge_location = "wsl"

    cur = mysql.connection.cursor()
    WSL_OUTPUT_DIR = "/home/hongxuan/ReconVault/output"

    try:
        user_prefix = f"{user_id}_"
        wsl_delete_pattern = f"{WSL_OUTPUT_DIR}/{user_prefix}*"

        # Keep your WSL deletion logic the same, just gate it.
        if purge_location in ("wsl", "both"):
            print(f"[DEBUG] Running: wsl rm -rf {wsl_delete_pattern}")

            result = subprocess.run(
                ["wsl", "-d", "kali-linux", "--", "rm", "-rf", wsl_delete_pattern],
                capture_output=True,
                text=True
            )

            print(f"[DEBUG] returncode: {result.returncode}")
            print(f"[DEBUG] stderr: {result.stderr}")

            if result.returncode != 0:
                raise Exception(f"WSL deletion failed: {result.stderr}")

            print(f"[SUCCESS] Deleted all {user_prefix}* from WSL")

        # NEW: Kali SSH purge (only if selected)
        if purge_location in ("kali", "both"):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=KALI_IP,
                    username=KALI_USER,
                    password=KALI_PASS,
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=15,
                    auth_timeout=15,
                    banner_timeout=15
                )

                remote_pattern = f"/home/kali/ReconVault/output/{user_prefix}*"
                rm_cmd = f"bash -lc {shlex.quote(f'rm -rf -- {remote_pattern}')}"
                ssh.exec_command(rm_cmd, get_pty=True)
                ssh.close()

                print(f"[DEBUG] Kali SSH deleted pattern: {remote_pattern}")
            except Exception as e:
                print(f"[WARN] Kali SSH purge skipped/failed: {e}")

        # DB purge: respect the selected location.
        if purge_location == "both":
            cur.execute("DELETE FROM reports WHERE user_id = %s", [user_id])
            mysql.connection.commit()
            print(f"[*] Database cleared for user {user_id} (both)")
        else:
            cur.execute("SELECT id, report_data FROM reports WHERE user_id = %s", [user_id])
            rows = cur.fetchall()

            ids_to_delete = []
            for rid, report_data in rows:
                try:
                    data = json.loads(report_data) if report_data else {}
                    is_kali = ("subdomains_all" in data or "subdomains_live" in data)
                except Exception:
                    # If parsing fails, treat as Local WSL to avoid accidentally deleting Kali results.
                    is_kali = False

                if purge_location == "kali" and is_kali:
                    ids_to_delete.append(rid)
                if purge_location == "wsl" and (not is_kali):
                    ids_to_delete.append(rid)

            if ids_to_delete:
                placeholders = ",".join(["%s"] * len(ids_to_delete))
                cur.execute(
                    f"DELETE FROM reports WHERE user_id = %s AND id IN ({placeholders})",
                    [user_id] + ids_to_delete
                )
                mysql.connection.commit()
                print(f"[*] Database cleared for user {user_id} (location={purge_location}, deleted={len(ids_to_delete)})")
            else:
                mysql.connection.commit()
                print(f"[*] No DB rows matched purge_location={purge_location} for user {user_id}")

        flash(f"All your reports have been purged. Location={purge_location.upper()}.", "success")

    except Exception as e:
        mysql.connection.rollback()
        print(f"[SYSTEM ERROR] {e}")
        flash(f"Error: {e}", "danger")

    finally:
        cur.close()

    return redirect(url_for('reports_page'))







def get_vt_api_key():
    try:
        if not os.path.exists(CFG_PATH): return None
        with open(CFG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                if 'VT_API_KEY=' in line and not line.strip().startswith('#'):
                    parts = line.split('=')
                    if len(parts) > 1:
                        return parts[1].strip().replace('"', '').replace("'", "")
    except Exception as e:
        print(f"[ERROR] Config read failed: {e}")
    return None



def get_cfg_value(key_name):
    # 1) environment first
    v = os.getenv(key_name)
    if v:
        return v.strip().strip('"').strip("'")

    # 2) candidate cfg paths
    candidate_paths = [
        "/home/hongxuan/ReconVault/reconvault.cfg",                    # Kali/WSL
        os.path.join(os.path.dirname(__file__), "reconvault.cfg"),    # local project root
        os.path.join(os.getcwd(), "reconvault.cfg"),
    ]

    for cfg_path in candidate_paths:
        try:
            if not os.path.exists(cfg_path):
                continue
            with open(cfg_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(rf'export\s+{re.escape(key_name)}=(.*)', line)
                    if m:
                        raw = m.group(1).strip()
                        return raw.strip('"').strip("'")
        except Exception:
            pass

    return None



def get_key_from_wsl_cfg(key_name, wsl_cfg="/home/hongxuan/ReconVault/reconvault.cfg"):
    if not re.match(r"^[A-Z0-9_]+$", key_name):
        return None

    # Windows-side env still wins if already set
    env_val = os.getenv(key_name)
    if env_val:
        return env_val.strip().strip('"').strip("'")

    try:
        result = subprocess.run(
            ["wsl", "-d", "kali-linux", "-u", "hongxuan", "cat", wsl_cfg],
            capture_output=True,
            text=True,
            timeout=8
        )

        if result.returncode != 0 or not result.stdout:
            return None

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = re.match(rf'^export\s+{re.escape(key_name)}=(.*)$', line)
            if match:
                raw = match.group(1).strip()
                return raw.strip('"').strip("'")

    except Exception as e:
        print(f"[ERROR] Failed reading WSL cfg for {key_name}: {e}")

    return None


def virustotal_url_scan(target_url, vt_api_key):
    headers = {"x-apikey": vt_api_key, "accept": "application/json"}

    # Submit URL
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": target_url},
        timeout=30
    )
    submit_json = submit.json() if "application/json" in submit.headers.get("Content-Type", "") else {}
    if submit.status_code != 200 or "data" not in submit_json:
        err = submit_json.get("error", {}).get("message", f"HTTP {submit.status_code}")
        return None, f"VirusTotal submit failed: {err}"

    analysis_id = submit_json["data"]["id"]

    # Poll analysis
    analysis_attrs = {}
    for _ in range(15):
        r = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=30
        )
        j = r.json()
        analysis_attrs = j.get("data", {}).get("attributes", {})
        if analysis_attrs.get("status") == "completed":
            break
        time.sleep(2)

    # Template expects result.data.last_analysis_stats
    result_data = {
    "analysis_id": analysis_id,
    "status": analysis_attrs.get("status", "queued"),
    "last_analysis_stats": analysis_attrs.get("stats", {}),
    "vt_link": f"https://www.virustotal.com/gui/url/{quote(target_url, safe='')}"
    }

    return result_data, None

@app.route("/run_tool", methods=["POST"])
@login_required
def run_tool():
    tool_type = (request.form.get("tool_type") or "").strip().lower()
    target = (request.form.get("tool_target") or "").strip()

    if not target:
        return render_template(
            "SeTools.html",
            error="Target is required.",
            result=None,
            recent_targets=get_recent_tool_targets()
        )

    if tool_type == "headers":
        try:
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"

            request_headers = {"User-Agent": "ReconVault/1.0"}

            try:
                resp = requests.get(
                    target,
                    timeout=(10, 20),
                    allow_redirects=True,
                    headers=request_headers
                )
            except requests.exceptions.ConnectTimeout:
                http_target = target.replace("https://", "http://", 1)
                resp = requests.get(
                    http_target,
                    timeout=(10, 20),
                    allow_redirects=True,
                    headers=request_headers
                )
                target = http_target

            sec_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy"
            ]

            header_result = {}
            for h in sec_headers:
                header_result[h] = "PROTECTED" if resp.headers.get(h) else "MISSING"

            push_recent_tool_target("headers", target)

            return render_template(
                "SeTools.html",
                result={
                    "type": "headers",
                    "target": target,
                    "data": header_result
                },
                recent_targets=get_recent_tool_targets()
            )

        except requests.exceptions.ConnectTimeout:
            return render_template(
                "SeTools.html",
                error="Connection timed out. The target may be offline, blocking your IP, or unreachable from this machine.",
                result=None,
                recent_targets=get_recent_tool_targets()
            )
        except requests.exceptions.ReadTimeout:
            return render_template(
                "SeTools.html",
                error="Target responded too slowly during header analysis.",
                result=None,
                recent_targets=get_recent_tool_targets()
            )
        except requests.exceptions.ConnectionError as e:
            return render_template(
                "SeTools.html",
                error=f"Could not connect to target: {e}",
                result=None,
                recent_targets=get_recent_tool_targets()
            )
        except Exception as e:
            return render_template(
                "SeTools.html",
                error=f"Header analysis failed: {e}",
                result=None,
                recent_targets=get_recent_tool_targets()
            )

    if tool_type == "virustotal":
        vt_key = get_key_from_wsl_cfg("VT_API_KEY")
        if not vt_key:
            return render_template(
                "SeTools.html",
                error="VT_API_KEY not found in WSL reconvault.cfg.",
                result=None,
                recent_targets=get_recent_tool_targets()
            )

        try:
            vt_data, err = virustotal_url_scan(target, vt_key)
            if err:
                return render_template(
                    "SeTools.html",
                    error=err,
                    result=None,
                    recent_targets=get_recent_tool_targets()
                )

            push_recent_tool_target("virustotal", target)

            return render_template(
                "SeTools.html",
                result={
                    "type": "virustotal",
                    "target": target,
                    "data": vt_data
                },
                recent_targets=get_recent_tool_targets()
            )
        except Exception as e:
            return render_template(
                "SeTools.html",
                error=f"VirusTotal request failed: {e}",
                result=None,
                recent_targets=get_recent_tool_targets()
            )

    return render_template(
        "SeTools.html",
        error="Unsupported tool selected.",
        result=None,
        recent_targets=get_recent_tool_targets()
    )


def get_recent_tool_targets(limit=5):
    recent = session.get("recent_tool_targets", [])
    if not isinstance(recent, list):
        return []
    return recent[:limit]


def push_recent_tool_target(tool_type, target):
    if not target:
        return

    recent = session.get("recent_tool_targets", [])
    if not isinstance(recent, list):
        recent = []

    item = {
        "tool_type": tool_type,
        "target": target.strip()
    }

    recent = [x for x in recent if not (x.get("tool_type") == tool_type and x.get("target") == target.strip())]
    recent.insert(0, item)
    session["recent_tool_targets"] = recent[:8]


@app.route("/setools")
def setools_page():
    if 'logged_in' not in session: 
        return redirect(url_for('login'))
    return render_template("SeTools.html", result=None)





@app.route('/settings')
def settings_page():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings_data = json.load(f)
         # forever enabled (indicator only)
            settings_data["data_encryption"] = True

            # (optional) persist it so settings.json is always correct
            with open(SETTINGS_FILE, "w") as f:
                json.dump(settings_data, f, indent=4)

        services = {
            "virustotal": bool(get_key_from_wsl_cfg("VT_API_KEY")),
            "shodan": bool(get_key_from_wsl_cfg("SHODAN_API_KEY")),
            "gemini": bool(get_key_from_wsl_cfg("GEMINI_API_KEY"))
        }


        if "threat_level" not in settings_data:
            settings_data["threat_level"] = "medium"

        timeout_defaults = {
            "subfinder_timeout": 60,
            "amass_timeout": 60,
            "gobuster_timeout": 300,
            "httpx_timeout": 60,
            "nuclei_timeout": 90
        }

        for key, value in timeout_defaults.items():
            if key not in settings_data:
                settings_data[key] = value

        return render_template('settings.html', settings=settings_data, services=services)
    except Exception:
        return "Error loading settings.", 500




@app.route('/kali-panel')
@login_required
def kali_panel():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    session.setdefault('kali_cwd', KALI_ALLOWED_BASE)

    return render_template(
        'kaliPanel.html',
        kali_host=KALI_IP,
        kali_user=KALI_USER,
        kali_base=KALI_ALLOWED_BASE
    )



@app.route('/api/kali/shell', methods=['POST'])
@login_required
def kali_shell():
    if 'logged_in' not in session:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json() or {}
    raw_command = (data.get('command') or '').strip()

    if not raw_command:
        return jsonify({"ok": False, "error": "No command provided"}), 400

    blocked_tokens = [';', '&&', '||', '|', '>', '>>', '<', '`', '$(']
    if any(token in raw_command for token in blocked_tokens):
        return jsonify({"ok": False, "error": "Blocked shell syntax"}), 400

    try:
        parts = shlex.split(raw_command)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid command syntax"}), 400

    if not parts:
        return jsonify({"ok": False, "error": "Empty command"}), 400

    command = parts[0]
    args = parts[1:]
    current_dir = session.get('kali_cwd', KALI_ALLOWED_BASE)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=KALI_IP,
            username=KALI_USER,
            password=KALI_PASS,
            look_for_keys=False,
            allow_agent=False,
            timeout=20,
            auth_timeout=20,
            banner_timeout=20
        )

        if command == 'clear':
            return jsonify({
                "ok": True,
                "cwd": current_dir,
                "command": raw_command,
                "output": "__CLEAR__"
            })

        if command == 'pwd':
            return jsonify({
                "ok": True,
                "cwd": current_dir,
                "command": raw_command,
                "output": current_dir
            })

        if command == 'cd':
            target = args[0] if args else KALI_ALLOWED_BASE

            if target == "~":
                new_dir = KALI_ALLOWED_BASE
            elif target.startswith("/"):
                new_dir = normalize_kali_path(target)
            else:
                new_dir = normalize_kali_path(posixpath.join(current_dir, target))

            if not is_allowed_kali_path(new_dir):
                return jsonify({"ok": False, "error": "Access denied: path outside allowed workspace"}), 403

            check_cmd = f"test -d {safe_shell_single_quote(new_dir)} && echo OK || echo NO"
            stdin, stdout, stderr = ssh.exec_command(check_cmd)
            exists = stdout.read().decode('utf-8', errors='replace').strip()

            if exists != "OK":
                return jsonify({"ok": False, "error": f"Directory not found: {new_dir}"}), 400

            session['kali_cwd'] = new_dir
            return jsonify({
                "ok": True,
                "cwd": new_dir,
                "command": raw_command,
                "output": f"Changed directory to {new_dir}"
            })

        allowed_commands = {'ls', 'cat', 'tail', 'whoami', 'hostname', 'pwd', 'cd ..'}
        if command not in allowed_commands:
            return jsonify({"ok": False, "error": f"Command not allowed: {command}"}), 400

        remote_cmd = ""
        quoted_cwd = safe_shell_single_quote(current_dir)

        if command == 'ls':
            target = args[0] if args else "."
            target_path = current_dir if target == "." else normalize_kali_path(posixpath.join(current_dir, target))

            if not is_allowed_kali_path(target_path):
                return jsonify({"ok": False, "error": "Access denied: path outside allowed workspace"}), 403

            remote_cmd = f"cd {quoted_cwd} && ls -lah {safe_shell_single_quote(target_path)}"

        elif command == 'cat':
            if not args:
                return jsonify({"ok": False, "error": "Usage: cat <file>"}), 400

            file_path = normalize_kali_path(posixpath.join(current_dir, args[0]))
            if not is_allowed_kali_path(file_path):
                return jsonify({"ok": False, "error": "Access denied: file outside allowed workspace"}), 403

            remote_cmd = f"cd {quoted_cwd} && cat {safe_shell_single_quote(file_path)}"

        elif command == 'tail':
            if len(args) >= 2 and args[0] == '-n':
                try:
                    lines = max(1, min(int(args[1]), 200))
                except ValueError:
                    return jsonify({"ok": False, "error": "Invalid tail line count"}), 400

                if len(args) < 3:
                    return jsonify({"ok": False, "error": "Usage: tail -n <lines> <file>"}), 400

                file_arg = args[2]
            else:
                lines = 50
                if not args:
                    return jsonify({"ok": False, "error": "Usage: tail <file> or tail -n <lines> <file>"}), 400
                file_arg = args[0]

            file_path = normalize_kali_path(posixpath.join(current_dir, file_arg))
            if not is_allowed_kali_path(file_path):
                return jsonify({"ok": False, "error": "Access denied: file outside allowed workspace"}), 403

            remote_cmd = f"cd {quoted_cwd} && tail -n {lines} {safe_shell_single_quote(file_path)}"

        elif command == 'whoami':
            remote_cmd = "whoami"

        elif command == 'hostname':
            remote_cmd = "hostname"
        

        elif command == 'pwd':
            remote_cmd = f"printf %s {safe_shell_single_quote(current_dir)}"

        stdin, stdout, stderr = ssh.exec_command(remote_cmd, get_pty=True)
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')

        return jsonify({
            "ok": True,
            "cwd": current_dir,
            "command": raw_command,
            "output": output.strip() if output.strip() else error.strip()
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    finally:
        ssh.close()


@app.route('/api/kali/health', methods=['GET'])
@login_required
def kali_health():
    if 'logged_in' not in session:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Fast handshake only: open + auth, then close.
        ssh.connect(
            hostname=KALI_IP,
            username=KALI_USER,
            password=KALI_PASS,
            look_for_keys=False,
            allow_agent=False,
            timeout=6,
            auth_timeout=6,
            banner_timeout=6
        )
        return jsonify({"ok": True, "host": KALI_IP, "user": KALI_USER})
    except Exception as e:
        return jsonify({"ok": False, "host": KALI_IP, "user": KALI_USER, "error": str(e)}), 200
    finally:
        try:
            ssh.close()
        except Exception:
            pass




@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'logged_in' not in session:
        return jsonify({"status": "error"}), 403

    try:
        settings = {}
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)

        for key in ['theme_mode', 'notifications', 'auto_scan', 'ssl_verification', 'threat_alerts', 'data_encryption']:
            settings[key] = key in request.form
            settings['data_encryption'] = True


        settings['language'] = request.form.get('language', 'English')
        settings['scan_timeout'] = int(request.form.get('scan_timeout', 300))
        settings['max_retries'] = int(request.form.get('max_retries', 3))

        threat_level = request.form.get('threat_level', 'medium').lower()
        settings['threat_level'] = threat_level

        # Core per-tool timeouts:
        # Threat Detection Level is a preset helper only; users can still override each field manually.
        # So we persist the explicit numeric fields from the form when provided.
        for key, default_val in [
            ('subfinder_timeout', default_settings.get('subfinder_timeout', 60)),
            ('amass_timeout', default_settings.get('amass_timeout', 60)),
            ('gobuster_timeout', default_settings.get('gobuster_timeout', 300)),
            ('httpx_timeout', default_settings.get('httpx_timeout', 60)),
            ('nuclei_timeout', default_settings.get('nuclei_timeout', 90)),
        ]:
            raw = request.form.get(key, '')
            try:
                if raw is None or str(raw).strip() == '':
                    settings[key] = int(settings.get(key, default_val))
                else:
                    settings[key] = int(raw)
            except Exception:
                settings[key] = int(settings.get(key, default_val))

        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=4)

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500




# --- DB payload safety (prevents MySQL max_allowed_packet crashes) ---
MAX_DB_REPORT_BYTES = 900_000  # Keep well under common max_allowed_packet defaults.

def _utf8_len(s: str) -> int:
    try:
        return len(s.encode("utf-8", errors="ignore"))
    except Exception:
        return len(str(s).encode("utf-8", errors="ignore"))

def _trim_multiline(text: str, max_lines: int) -> tuple[str, bool, int]:
    lines = (text or "").splitlines()
    total = len(lines)
    if total <= max_lines:
        return text, False, total
    kept = "\n".join(lines[:max_lines])
    kept += f"\n... [TRUNCATED {total - max_lines} lines]\n"
    return kept, True, total

def shrink_report_for_db(report_data: dict, max_bytes: int = MAX_DB_REPORT_BYTES) -> dict:
    """
    Ensures JSON payload fits into typical MySQL packet limits by truncating
    very large multiline fields (subdomains/web/params/vulns/etc).
    """
    if not isinstance(report_data, dict):
        return {"_error": "invalid report_data type"}

    data = dict(report_data)

    def payload_size(d: dict) -> int:
        return _utf8_len(json.dumps(d, ensure_ascii=False))

    if payload_size(data) <= max_bytes:
        return data

    trim_order = [
        "subdomains_all",
        "subdomains",
        "subdomains_live",
        "web",
        "parameters",
        "vulnerabilities",
        "osint",
        "hosts",
    ]

    truncated = []
    line_caps = [5000, 2000, 1000, 500, 200]

    for key in trim_order:
        if payload_size(data) <= max_bytes:
            break

        val = data.get(key)
        if not isinstance(val, str) or "\n" not in val:
            continue

        original_lines = len(val.splitlines())
        for cap in line_caps:
            trimmed, did, _ = _trim_multiline(val, cap)
            if did:
                data[key] = trimmed
                truncated.append(f"{key}:{original_lines}->{cap}")
            if payload_size(data) <= max_bytes:
                break

    while payload_size(data) > max_bytes:
        biggest_key = None
        biggest_size = 0
        for k, v in data.items():
            if isinstance(v, str):
                sz = _utf8_len(v)
                if sz > biggest_size:
                    biggest_size = sz
                    biggest_key = k
        if not biggest_key:
            break
        data[biggest_key] = f"[TRUNCATED] Removed '{biggest_key}' due to DB payload size limits."
        truncated.append(f"{biggest_key}:dropped")

    if truncated:
        data["_db_note"] = "DB payload truncated to avoid MySQL max_allowed_packet."
        data["_db_truncated_fields"] = ", ".join(truncated[:50])

    return data


if __name__ == "__main__":
    # host='0.0.0.0' allows your Windows laptop to talk to this Kali PC
    app.run(host="0.0.0.0", port=5000, debug=False)
