import os
import sys
import sqlite3
import hashlib
import uuid
import subprocess
import threading
import time
import queue
import logging
import signal
import shutil
import requests 
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- CONFIGURATION ---
class Config:
    SECRET_KEY = 'peak-secret-key-dev-mode'
    DATABASE_PATH = os.path.join(os.getcwd(), 'data', 'peak.db')
    LOG_DIR = os.path.join(os.getcwd(), 'logs')
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config['DATABASE'] = Config.DATABASE_PATH
app.config['LOG_DIR'] = Config.LOG_DIR
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER

for path in [app.config['LOG_DIR'], app.config['UPLOAD_FOLDER'], os.path.dirname(app.config['DATABASE'])]:
    os.makedirs(path, exist_ok=True)

logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler()])
logger = logging.getLogger("PEAK_CORE")

# --- PATHS ---
SCRCPY_PATH = r"C:\Users\RubeshwaranChokkalin\Downloads\scrcpy-win64-v3.3.4\scrcpy-win64-v3.3.4\scrcpy.exe"
FFMPEG_BIN = "ffmpeg" 

POSSIBLE_MEMU_PATHS = [
    r"C:\Program Files\Microvirt\MEmu\adb.exe",
    r"D:\Program Files\Microvirt\MEmu\adb.exe",
    r"E:\Program Files\Microvirt\MEmu\adb.exe"
]
ADB_PATH = "adb"
for path in POSSIBLE_MEMU_PATHS:
    if os.path.exists(path):
        ADB_PATH = path
        os.environ['ADB'] = ADB_PATH 
        break
EMULATOR_TARGET = "127.0.0.1:21503"

# --- 3. iOS CONTROLLER (PURE pymobiledevice3) ---
class IosController:
    def __init__(self):
        self.tunnel_proc = None
        self.port = 8100 
        self.mjpeg_url = f"http://127.0.0.1:{self.port}/mjpeg"
        self.session_url = f"http://127.0.0.1:{self.port}/session"
        self.session_id = None
        # YOUR BUNDLE ID
        self.bundle_id = "com.shamanec.WebDriverAgentRunner.xctrunner.Z2ZD46T5VE"

    def start_bridge(self):
        logger.info("🍎 Initializing Pure iOS Bridge...")
        python_exe = sys.executable

        # 1. CLEANUP
        subprocess.run("taskkill /F /IM python.exe /FI \"WINDOWTITLE eq pymobiledevice3*\"", shell=True, stderr=subprocess.DEVNULL)

        # 2. MOUNT DDI (Required for automation)
        try:
            logger.info("🍎 Mounting Developer Image...")
            subprocess.run([python_exe, "-m", "pymobiledevice3", "mounter", "auto-mount"], capture_output=True)
        except: pass

        # 3. START TUNNEL & FORWARD
        # We launch a tunnel that AUTOMATICALLY forwards port 8100 from the device
        # Command: python -m pymobiledevice3 remote tunnel --script-mode --forward 8100 8100
        try:
            tunnel_cmd = [
                python_exe, "-m", "pymobiledevice3", 
                "remote", "tunnel", 
                "--script-mode", 
                "--forward", "8100", "8100" # Maps PC:8100 -> Phone:8100
            ]
            self.tunnel_proc = subprocess.Popen(tunnel_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("🍎 Secure Tunnel & Forwarding Started.")
            
            # Start connection loop
            threading.Thread(target=self._launch_and_monitor).start()
            return True
        except Exception as e:
            logger.error(f"Tunnel Failed: {e}")
            return False

    def _launch_and_monitor(self):
        """Launches App and maintains connection"""
        python_exe = sys.executable
        time.sleep(3) # Wait for tunnel init

        # 1. Launch WDA
        try:
            logger.info(f"🍎 Launching App: {self.bundle_id}")
            subprocess.run([python_exe, "-m", "pymobiledevice3", "apps", "launch", self.bundle_id], capture_output=True)
        except: pass

        # 2. Connect Loop
        for i in range(20): # Retry for 20 seconds
            time.sleep(1)
            if self._init_session():
                logger.info("✅ iOS Bridge Fully Operational!")
                return
            logger.warning(f"🍎 Waiting for WDA... ({i+1}/20)")
            
            # Re-launch app if it takes too long (sometimes it needs a kick)
            if i % 5 == 0 and i > 0:
                logger.info("🍎 Re-sending Launch Command...")
                subprocess.run([python_exe, "-m", "pymobiledevice3", "apps", "launch", self.bundle_id], capture_output=True)

    def _init_session(self):
        try:
            res = requests.post(self.session_url, json={"capabilities": {}}, timeout=2)
            if res.status_code == 200:
                self.session_id = res.json().get('sessionId')
                return True
        except: pass
        return False

    def get_frame_proxy(self):
        while True:
            try:
                req = requests.get(self.mjpeg_url, stream=True, timeout=5)
                if req.status_code == 200:
                    for chunk in req.iter_content(chunk_size=4096): yield chunk
                else: time.sleep(1)
            except: time.sleep(1)

    def tap(self, x_ratio, y_ratio):
        if not self.session_id: self._init_session()
        width, height = 375, 812 
        try: requests.post(f"{self.session_url}/{self.session_id}/wda/tap/0", json={"x": x_ratio*width, "y": y_ratio*height}, timeout=1)
        except: pass

    def home_button(self):
        if not self.session_id: self._init_session()
        try: requests.post(f"{self.session_url}/{self.session_id}/wda/homescreen", timeout=1)
        except: pass

ios_ctrl = IosController()

# --- 4. ANDROID CONTROLLER ---
class AndroidController:
    def __init__(self):
        self.video_queue = queue.Queue(maxsize=2)
        self.mode = "compat"
        self.running = False

    def start_stream(self):
        if self.running: return
        self.running = True
        try: subprocess.run([ADB_PATH, "connect", EMULATOR_TARGET], capture_output=True, timeout=2)
        except: pass
        threading.Thread(target=self._run_scrcpy if self.mode == "turbo" else self._run_screencap, daemon=True).start()

    def _run_scrcpy(self):
        scrcpy_cmd = [SCRCPY_PATH, "--serial", EMULATOR_TARGET, "--no-audio", "--video-codec", "h264", "-"]
        ffmpeg_cmd = [FFMPEG_BIN, "-f", "h264", "-i", "pipe:0", "-f", "mjpeg", "-vf", "scale=800:-1", "-q:v", "5", "pipe:1"]
        try:
            scrcpy_proc = subprocess.Popen(scrcpy_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            ffmpeg_proc = subprocess.Popen(ffmpeg_cmd, stdin=scrcpy_proc.stdout, stdout=subprocess.PIPE, bufsize=0)
            while self.running:
                chunk = ffmpeg_proc.stdout.read(8192)
                if not chunk: break
                self._buffer(chunk)
        except:
            self.mode = "compat"
            self.running = False
            time.sleep(1)
            self.start_stream()

    def _run_screencap(self):
        while self.running:
            try:
                cmd = [ADB_PATH, "-s", EMULATOR_TARGET, "exec-out", "screencap", "-p"]
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate(timeout=3)
                if out: self._buffer(out)
                time.sleep(0.05)
            except: time.sleep(1)

    def _buffer(self, data):
        if self.video_queue.full():
            try: self.video_queue.get_nowait()
            except: pass
        self.video_queue.put(data)

    def get_frame(self):
        if not self.running: self.start_stream()
        while True:
            try:
                frame = self.video_queue.get(timeout=2)
                mime = 'image/jpeg' if self.mode == 'turbo' else 'image/png'
                yield (b'--frame\r\nContent-Type: ' + mime.encode() + b'\r\n\r\n' + frame + b'\r\n')
            except: 
                self.running = False
                time.sleep(1)
                self.start_stream()

    def tap(self, x, y):
        rx, ry = int(x * 1080), int(y * 1920)
        subprocess.Popen([ADB_PATH, "-s", EMULATOR_TARGET, "shell", "input", "tap", str(rx), str(ry)])

    def key(self, code):
        subprocess.Popen([ADB_PATH, "-s", EMULATOR_TARGET, "shell", "input", "keyevent", str(code)])

android_ctrl = AndroidController()

# --- 5. BOILERPLATE ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None: db = g._database = sqlite3.connect(app.config['DATABASE']); db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        get_db().execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, twofa_secret TEXT)')
        get_db().execute('CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, user_id INTEGER, name TEXT, created_at TIMESTAMP)')
        get_db().commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs) if 'user_id' in session else redirect(url_for('login'))
    return decorated

@app.route('/')
def index(): return redirect(url_for('home')) if 'user_id' in session else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (request.form['username'],)).fetchone()
        if user and check_password_hash(user['password_hash'], request.form['password']):
            session.update({'user_id': user['id'], 'username': user['username']})
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            get_db().execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (request.form['username'], generate_password_hash(request.form['password'])))
            get_db().commit()
            return redirect(url_for('login'))
        except: pass
    return render_template('register.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/home')
@login_required
def home(): return render_template('home.html', username=session.get('username'))

@app.route('/dashboard')
@login_required
def dashboard():
    projects = get_db().execute("SELECT * FROM projects WHERE user_id = ?", (session['user_id'],)).fetchall()
    return render_template('dashboard.html', username=session['username'], projects=projects, current_project_id=session.get('current_project_id'), current_project_name=session.get('current_project_name'))

@app.route('/create_project', methods=['POST'])
@login_required
def create_project_route():
    pid = str(uuid.uuid4())
    get_db().execute("INSERT INTO projects (id, user_id, name) VALUES (?, ?, ?)", (pid, session['user_id'], request.form['project_name']))
    get_db().commit()
    session.update({'current_project_id': pid, 'current_project_name': request.form['project_name']})
    return redirect(url_for('dashboard'))

@app.route('/select_project/<pid>', methods=['POST'])
@login_required
def select_project_route(pid):
    proj = get_db().execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
    if proj: session.update({'current_project_id': pid, 'current_project_name': proj['name']})
    return redirect(url_for('dashboard'))

@app.route("/api/mobile/launch_emulator", methods=["POST"])
@login_required
def launch_emulator():
    exe = ADB_PATH.replace("adb.exe", "MEmu.exe")
    if os.path.exists(exe):
        subprocess.Popen([exe], shell=True)
        android_ctrl.mode = "turbo"; android_ctrl.start_stream()
        return jsonify({"status": "success", "message": "MEmu Launching..."})
    return jsonify({"status": "error"})

@app.route("/api/mobile/video_feed")
def mobile_video(): return Response(android_ctrl.get_frame(), mimetype="multipart/x-mixed-replace; boundary=frame")

@app.route("/api/mobile/touch", methods=["POST"])
def mobile_touch(): android_ctrl.tap(request.json.get("x"), request.json.get("y")); return jsonify({"status": "ok"})

@app.route("/api/mobile/key", methods=["POST"])
def mobile_key(): 
    k = {"home": "3", "back": "4", "menu": "82"}
    if request.json.get("action") in k: android_ctrl.key(k[request.json.get("action")])
    return jsonify({"status": "ok"})

@app.route("/api/mobile/install", methods=["POST"])
def install_apk():
    f = request.files['file']
    path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
    f.save(path)
    try: subprocess.run([ADB_PATH, "-s", EMULATOR_TARGET, "install", "-r", path]); os.remove(path); return jsonify({"status": "success"})
    except: return jsonify({"status": "error"})

@app.route("/api/ios/connect", methods=["POST"])
def ios_connect(): return jsonify({"status": "success", "message": "iOS Bridge Active"}) if ios_ctrl.start_bridge() else jsonify({"status": "error"})

@app.route("/api/ios/video_feed")
def ios_video(): return Response(ios_ctrl.get_frame_proxy(), mimetype='multipart/x-mixed-replace; boundary=--boundary')

@app.route("/api/ios/touch", methods=["POST"])
def ios_touch(): ios_ctrl.tap(float(request.json.get('x')), float(request.json.get('y'))); return jsonify({"status": "ok"})

@app.route("/api/ios/home", methods=["POST"])
def ios_home(): ios_ctrl.home_button(); return jsonify({"status": "ok"})

@app.route('/agent_command', methods=['POST'])
def a(): return jsonify({"status":"success", "response_for_ui": "Agent Active"})

if __name__ == '__main__': init_db(); app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)