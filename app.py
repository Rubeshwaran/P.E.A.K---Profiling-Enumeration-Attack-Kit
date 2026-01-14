import os
import sqlite3
import hashlib
import pyotp
import qrcode
import base64
import json
import logging
import uuid
import shutil
import csv
import io
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g, current_app, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests
import re

# Import the individual modules
from modules.network_discovery import NetworkDiscoveryModule
from modules.ip_scan import IPScanModule
from modules.osint_module import OSINTModule
from config import Config
from tools.mobile_scanner import MobileScanner

# Import P.E.A.K Modules
from modules.peak_profiler import PeakProfiler
from modules.peak_ai import PeakAI

# --- 1. INITIALIZE FLASK APP FIRST ---
app = Flask(__name__)
app.secret_key = Config.FLASK_SECRET_KEY
app.config['DATABASE'] = Config.DATABASE_PATH
app.config['LOG_DIR'] = Config.LOG_DIR
app.config['LLM_API_URL'] = Config.LLM_API_URL
app.config['LLM_MODEL_NAME'] = Config.LLM_MODEL_NAME
app.config['LLM_API_KEY'] = Config.LLM_API_KEY

# --- 2. CONFIGURE LOGGING ---
os.makedirs(app.config['LOG_DIR'], exist_ok=True)
os.makedirs(Config.DATA_DIR, exist_ok=True)

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(os.path.join(app.config['LOG_DIR'], 'app.log')),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

# --- 3. CONFIGURE UPLOAD FOLDER & TOOLS ---
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize Tools
mobile_tool = MobileScanner()
peak_profiler = PeakProfiler()
peak_ai = PeakAI()

# --- 4. DATABASE SETUP ---
def get_db():
    """Establishes a database connection or returns the current one."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row 
    return db

def init_db():
    """Initializes the SQLite database and creates necessary tables."""
    db = get_db()
    cursor = db.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            twofa_secret TEXT
        )
    ''')

    # Projects table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            name TEXT NOT NULL,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (id)
        )
    ''')

    # Command History table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_command TEXT NOT NULL,
            module_name TEXT,
            target TEXT,
            ports TEXT,
            structured_results TEXT, -- Stored as JSON string
            raw_output TEXT,
            llm_analysis TEXT,
            status TEXT NOT NULL, -- 'success', 'error', 'pending'
            message TEXT,       -- Added back the 'message' column
            FOREIGN KEY (session_id) REFERENCES sessions (id),
            FOREIGN KEY (project_id) REFERENCES projects (id)
        )
    ''')
    db.commit()
    logger.info("Database initialized successfully.")

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- 5. HELPER FUNCTIONS ---

def _format_text_for_html_display(text):
    """Helper function to convert newline characters to <br> tags for HTML display."""
    if not isinstance(text, str):
        return str(text)
    return text.replace('\n\n', '<br><br>').replace('\n', '<br>')

def get_project_by_id(project_id):
    db = get_db()
    return db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()

def create_session_db(project_id, session_name):
    db = get_db()
    session_id = str(uuid.uuid4())
    try:
        db.execute("INSERT INTO sessions (id, project_id, name) VALUES (?, ?, ?)",
                   (session_id, project_id, session_name))
        db.commit()
        return session_id
    except sqlite3.Error as e:
        logger.error(f"Database error creating session: {e}")
        return None

def end_session_in_db(session_id):
    db = get_db()
    try:
        db.execute("UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE id = ?", (session_id,))
        db.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error ending session: {e}")

def create_project_db(user_id, project_name):
    db = get_db()
    project_id = str(uuid.uuid4())
    try:
        db.execute("INSERT INTO projects (id, user_id, name) VALUES (?, ?, ?)",
                   (project_id, user_id, project_name))
        db.commit()
        return project_id
    except Exception as e:
        logger.error(f"Error creating project: {e}")
        return None

def save_command_result(project_id, session_id, user_command, module_name, target, status, message, structured_results, raw_output, llm_analysis):
    conn = get_db()
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    try:
        cursor.execute(
            "INSERT INTO command_history (project_id, session_id, user_command, module_name, target, status, message, structured_results, raw_output, llm_analysis, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (project_id, session_id, user_command, module_name, target, status, message, json.dumps(structured_results), raw_output, llm_analysis, timestamp)
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error saving command result: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Unexpected error saving command result: {e}", exc_info=True)

def get_project_command_history(project_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM command_history WHERE project_id = ? ORDER BY timestamp DESC", (project_id,))
    history = cursor.fetchall()
    return history

# --- 6. AI AGENT CLASS ---
class AIAgent:
    def __init__(self, modules_dict):
        self.modules_dict = modules_dict

    def get_module_instance(self, module_name, session_id, project_name):
        module_class = self.modules_dict.get(module_name)
        if module_class:
            return module_class(session_id=session_id, project_name=project_name)
        return None

    def _call_llm_api(self, prompt, is_general_query=False):
        llm_api_url = current_app.config['LLM_API_URL']
        llm_api_key = current_app.config['LLM_API_KEY']
        llm_model_name = current_app.config['LLM_MODEL_NAME']

        format_func = _format_text_for_html_display

        if not llm_api_url or not llm_api_key or not llm_model_name:
            logger.warning("LLM API URL, API Key, or Model Name not configured. Skipping LLM analysis.")
            return format_func("LLM analysis skipped: Configuration missing.")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {llm_api_key}" if llm_api_key else None
        }
        headers = {k: v for k, v in headers.items() if v is not None}

        data_for_llm = {
            "model": llm_model_name,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.2
        }

        try:
            response = requests.post(llm_api_url, headers=headers, json=data_for_llm, timeout=300)
            response.raise_for_status()

            llm_response_data = response.json()
            
            logger.debug(f"Raw LLM API Response Data: {json.dumps(llm_response_data, indent=2)}")

            if 'choices' in llm_response_data and llm_response_data['choices']:
                first_choice = llm_response_data['choices'][0]
                if 'message' in first_choice and 'content' in first_choice['message']:
                    raw_llm_content = first_choice['message']['content']
                    cleaned_content = raw_llm_content.strip('\"')
                    
                    if is_general_query:
                        return format_func(cleaned_content)
                    else:
                        return format_func(cleaned_content)

            logger.warning(f"Unexpected LLM response structure: {llm_response_data}")
            return format_func("LLM analysis failed: Unexpected response format from LLM API.")

        except requests.exceptions.Timeout:
            logger.error(f"LLM analysis failed: Request timed out after {300} seconds.")
            return format_func("LLM analysis failed: Request timed out.")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"LLM analysis failed: Connection error: {e}")
            return format_func(f"LLM analysis failed: Connection error: {e}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"LLM analysis failed: HTTP error {e.response.status_code}: {e.response.text}")
            return format_func(f"LLM analysis failed: HTTP error {e.response.status_code}: {e.response.text}")
        except Exception as e:
            logger.error(f"LLM analysis failed: An unexpected error occurred: {e}", exc_info=True)
            return format_func(f"LLM analysis failed: An unexpected error occurred: {e}")

# --- 7. ROUTES ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- P.E.A.K ANALYSIS ROUTE (Active Recon + AI) ---
@app.route('/api/peak/analyze', methods=['POST'])
@login_required
def peak_analyze():
    data = request.get_json()
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({"status": "error", "message": "No URL provided"})

    # 1. Active Profiling
    profile_result = peak_profiler.analyze_url(target_url)
    
    if profile_result['status'] == 'error':
        return jsonify(profile_result)

    detected_stack = profile_result['tech_stack']
    exposed_paths = profile_result.get('exposed_paths', [])

    # 2. AI Planning (Now with finding context)
    ai_plan = peak_ai.generate_attack_plan(detected_stack, exposed_paths)

    return jsonify({
        "status": "success",
        "url": target_url,
        "tech_stack": detected_stack,
        "exposed_paths": exposed_paths, # Send back to UI for red alert
        "ai_plan_html": _format_text_for_html_display(ai_plan), # HTML for Display
        "ai_plan_raw": ai_plan # Raw text for Export
    })

# --- P.E.A.K EXPORT ROUTE (New CSV Feature) ---
@app.route('/api/peak/export', methods=['POST'])
@login_required
def export_peak_report():
    data = request.get_json()
    
    # 1. Create CSV in Memory
    si = io.StringIO()
    cw = csv.writer(si)
    
    # 2. Write Metadata
    cw.writerow(['P.E.A.K. INTELLIGENCE REPORT'])
    cw.writerow(['Target URL', data.get('url', 'Unknown')])
    cw.writerow(['Scan Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    cw.writerow([]) # Empty row
    
    # 3. Write Tech Stack
    cw.writerow(['--- TECHNOLOGY STACK ---'])
    for tech in data.get('tech_stack', []):
        cw.writerow([tech])
    cw.writerow([])

    # 4. Write Exposed Paths
    cw.writerow(['--- EXPOSED PATHS / VULNERABILITIES ---'])
    paths = data.get('exposed_paths', [])
    if paths:
        for path in paths:
            cw.writerow([path, 'CRITICAL - Publicly Accessible'])
    else:
        cw.writerow(['No sensitive paths detected via active probing.'])
    cw.writerow([])

    # 5. Write AI Attack Plan
    cw.writerow(['--- AI ATTACK PLAN (PHI-3) ---'])
    # Clean up the plan text slightly for CSV
    plan_text = data.get('ai_plan_raw', 'No plan generated.')
    cw.writerow([plan_text])
    
    # 6. Return as Downloadable File
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=PEAK_Report_{int(datetime.now().timestamp())}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/api/scan/mobile', methods=['POST'])
@login_required
def scan_mobile():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"})

    if file:
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        
        # Run the scan using our new tool
        scan_result = mobile_tool.upload_and_scan(save_path)
        
        return jsonify({
            "status": "success", 
            "security_score": scan_result.get('security_score', 'N/A'),
            "high_issues": scan_result.get('high_issues', []), # Updated to match robust parser
            "full_report": scan_result
        })

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash("Username and password cannot be empty.", "danger")
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists. Please choose a different one.", "warning")
        else:
            password_hash = generate_password_hash(password)
            try:
                db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, password_hash))
                db.commit()
                flash("Registration successful! Please log in.", "success")
                logger.info(f"User {username} registered successfully.")
                return redirect(url_for('login'))
            except sqlite3.Error as e:
                flash(f"Database error during registration: {e}", "danger")
                logger.error(f"Database error during registration for user {username}: {e}")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        twofa_code = request.form.get('2fa_code')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, password_hash, twofa_secret FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            if user['twofa_secret']:
                if not twofa_code:
                    flash("2FA is enabled for this account. Please enter your 2FA code.", "info")
                    return render_template('login.html', show_2fa_input=True, username=username)
                
                totp = pyotp.TOTP(user['twofa_secret'])
                if not totp.verify(twofa_code):
                    flash("Invalid 2FA code.", "danger")
                    return render_template('login.html', show_2fa_input=True, username=username)

            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("Logged in successfully!", "success")
            logger.info(f"User {username} logged in.")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if 'current_session_id' in session:
        end_session_in_db(session['current_session_id'])
        logger.info(f"Session {session['current_session_id']} ended due to logout.")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    username = session.get('username')
    
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, name FROM projects WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    projects = cursor.fetchall()

    cursor.execute("SELECT twofa_secret FROM users WHERE id = ?", (user_id,))
    user_settings = cursor.fetchone()
    is_2fa_enabled = bool(user_settings and user_settings['twofa_secret'])
    qr_code_base64 = None
    temp_2fa_secret = None

    if not is_2fa_enabled and request.args.get('setup_2fa') == 'true':
        temp_2fa_secret = pyotp.random_base32()
        session['temp_2fa_secret'] = temp_2fa_secret
        
        otp_uri = pyotp.totp.TOTP(temp_2fa_secret).provisioning_uri(
            name=username,
            issuer_name="VISTO"
        )
        img = qrcode.make(otp_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    current_project_id = session.get('current_project_id')
    current_project_name = session.get('current_project_name')
    current_session_id = session.get('current_session_id')

    # FIX: Force recent history to None so it doesn't "stick" on refresh
    most_recent_command_output = None 

    return render_template('dashboard.html',
                           username=username,
                           projects=projects,
                           is_2fa_enabled=is_2fa_enabled,
                           qr_code_base64=qr_code_base64,
                           temp_2fa_secret=temp_2fa_secret,
                           current_project_id=current_project_id,
                           current_project_name=current_project_name,
                           current_session_id=current_session_id,
                           most_recent_command_output=most_recent_command_output)

@app.route('/toggle_2fa', methods=['POST'])
@login_required
def toggle_2fa():
    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT twofa_secret FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if user and user['twofa_secret']:
        db.execute("UPDATE users SET twofa_secret = NULL WHERE id = ?", (user_id,))
        db.commit()
        flash("Two-factor authentication disabled.", "info")
        logger.info(f"User {session['username']} disabled 2FA.")
    else:
        flash("Please scan the QR code to set up 2FA.", "info")
        return redirect(url_for('dashboard', setup_2fa='true'))
    
    return redirect(url_for('dashboard'))

@app.route('/verify_2fa_setup', methods=['POST'])
@login_required
def verify_2fa_setup():
    user_id = session['user_id']
    user_input_code = request.form.get('2fa_code')
    temp_secret = session.get('temp_2fa_secret')

    if not temp_secret:
        flash("2FA setup not initiated or session expired. Please try again.", "danger")
        return redirect(url_for('dashboard'))

    if not user_input_code:
        flash("Please enter the 2FA code.", "danger")
        return redirect(url_for('dashboard', setup_2fa='true'))

    totp = pyotp.TOTP(temp_secret)
    if totp.verify(user_input_code):
        db = get_db()
        db.execute("UPDATE users SET twofa_secret = ? WHERE id = ?", (temp_secret, user_id))
        db.commit()
        session.pop('temp_2fa_secret', None)
        flash("Two-factor authentication successfully enabled!", "success")
        logger.info(f"User {session['username']} enabled 2FA.")
    else:
        flash("Invalid 2FA code. Please try again.", "danger")
        return redirect(url_for('dashboard', setup_2fa='true'))

    return redirect(url_for('dashboard'))

@app.route('/create_project', methods=['POST'])
@login_required
def create_project_route():
    project_name = request.form['project_name']
    user_id = session['user_id']
    if not project_name:
        flash("Project name cannot be empty.", "danger")
    else:
        project_id = create_project_db(user_id, project_name)
        if project_id:
            flash(f"Project '{project_name}' created successfully!", "success")
            logger.info(f"User {session['username']} created project {project_name} ({project_id}).")
            session['current_project_id'] = project_id
            session['current_project_name'] = project_name
            
            session_name = f"Initial Session for {project_name} - {datetime.now().strftime('%Y%m%d%H%M%S')}"
            current_session_id = create_session_db(project_id, session_name)
            if current_session_id:
                session['current_session_id'] = current_session_id
                flash(f"New session '{session_name}' started.", "info")
                logger.info(f"New session {current_session_id} started for project {project_id}.")
            else:
                flash("Failed to create an initial session for the project.", "warning")
                logger.error(f"Failed to create initial session for project {project_id}.")
        else:
            flash("Failed to create project. Please try again.", "danger")
            logger.error(f"Failed to create project {project_name} for user {user_id}.")
    return redirect(url_for('dashboard'))

@app.route('/select_project/<project_id>', methods=['POST'])
@login_required
def select_project_route(project_id):
    user_id = session['user_id']
    project = get_project_by_id(project_id)
    if project and project['user_id'] == user_id:
        if session.get('current_session_id'):
            end_session_in_db(session['current_session_id'])
            logger.info(f"Session {session['current_session_id']} ended due to project change.")

        session['current_project_id'] = project_id
        session['current_project_name'] = project['name']
        
        session_name = f"Session for {project['name']} - {datetime.now().strftime('%Y%m%d%H%M%S')}"
        current_session_id = create_session_db(project_id, session_name)
        
        if current_session_id:
            session['current_session_id'] = current_session_id
            flash(f"Project '{project['name']}' selected and new session started.", "success")
            logger.info(f"Project {project_id} selected. New session {current_session_id} created.")
        else:
            flash("Failed to create a new session for the selected project.", "warning")
            logger.error(f"Failed to create session for selected project {project_id}.")

    else:
        flash("Project not found or you don't have access.", "danger")
        logger.warning(f"User {session['username']} attempted to select unauthorized project {project_id}.")
    return redirect(url_for('dashboard'))

@app.route('/delete_project/<project_id>', methods=['POST'])
@login_required
def delete_project_route(project_id):
    db = get_db()
    project = get_project_by_id(project_id)
    if project and project['user_id'] == session['user_id']:
        project_name = project['name']
        if session.get('current_project_id') == project_id:
            if 'current_session_id' in session:
                end_session_in_db(session['current_session_id'])
            session.pop('current_project_id', None)
            session.pop('current_project_name', None)
            session.pop('current_session_id', None)

        try:
            db.execute("DELETE FROM command_history WHERE project_id = ?", (project_id,))
            db.execute("DELETE FROM sessions WHERE project_id = ?", (project_id,))
            db.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            db.commit()

            project_data_path = os.path.join(Config.DATA_DIR, session['username'], project_name)
            if os.path.exists(project_data_path):
                shutil.rmtree(project_data_path)

            flash(f"Project '{project_name}' and all associated data deleted.", "success")
            logger.info(f"User {session['username']} deleted project {project_name} ({project_id}).")
        except Exception as e:
            flash(f"Error deleting project: {e}", "danger")
            logger.error(f"Error deleting project {project_id} for user {session['username']}: {e}")
    else:
        flash("Project not found or you don't have access.", "danger")
        logger.warning(f"User {session['username']} attempted to delete unauthorized project {project_id}.")
    return redirect(url_for('dashboard'))

@app.route('/project_history/<project_id>')
@login_required
def project_history(project_id):
    user_id = session.get('user_id')
    project = get_project_by_id(project_id)

    if not project or project['user_id'] != user_id:
        flash("Project not found or you don't have access.", "danger")
        return redirect(url_for('dashboard'))

    history = get_project_command_history(project_id)
    formatted_history = []
    for entry in history:
        mutable_entry = dict(entry)
        formatted_history.append(mutable_entry)

    return render_template('project_history.html', project_name=project['name'], history=formatted_history)

@app.route('/agent_command', methods=['POST'])
@login_required
def process_command():
    user_id = session.get('user_id')
    current_session_id = session.get('current_session_id')
    project_id = session.get('current_project_id')
    project_name = session.get('current_project_name')

    if not all([user_id, current_session_id, project_id, project_name]):
        return jsonify({'status': 'error', 'message': 'Session or project not fully established.'}), 400

    data = request.get_json()
    command_string = data.get('command')
    if not command_string:
        return jsonify({'status': 'error', 'message': 'No command provided.'}), 400

    try:
        command_parts = command_string.split(' ')
        module_name = command_parts[0].lower()
        
        # --- COMMAND ALIASING ---
        if module_name == 'scan':
            module_name = 'ip_scan'
        
        command_args = command_parts[1:]

        params = {
            'user_command': command_string,
            'module_name': module_name,
            'session_id': current_session_id,
            'project_name': project_name
        }

        # --- ASK AI / HELP ---
        if module_name == 'ask_ai':
            user_query = " ".join(command_args)
            response_text = current_app.agent_instance._call_llm_api(
                f"User asked: {user_query}. Provide a concise and helpful answer.",
                is_general_query=True
            )
            return jsonify({
                "status": "success",
                "message": response_text,
                "response_for_ui": response_text,
                "user_command": command_string,
                "module_name": module_name,
                "raw_output": response_text
            })
        
        elif module_name == 'help':
            help_text = "Usage: scan <ip> | osint <ip/domain> | ask_ai <query>"
            return jsonify({
                "status": "success",
                "message": help_text,
                "response_for_ui": help_text
            })

        # --- MODULE EXECUTION ---
        elif module_name in ['network_discovery', 'ip_scan', 'osint']:
            # ... (Parameter parsing logic as before) ...
            if module_name == 'ip_scan':
                if len(command_args) < 1:
                    return jsonify({"status": "error", "message": "Usage: scan <target>"})
                params['target'] = command_args[0]
                params['target_ip'] = command_args[0]
            
            elif module_name == 'network_discovery':
                if len(command_args) < 1:
                    return jsonify({"status": "error", "message": "Usage: network_discovery <cidr>"})
                params['target'] = command_args[0]
                params['target_ip_range_or_subnet'] = command_args[0]

            elif module_name == 'osint':
                if len(command_args) < 2:
                    return jsonify({"status": "error", "message": "Usage: osint <type> <target>"})
                params['target_type'] = command_args[0]
                params['target'] = command_args[1]

            module_instance = current_app.agent_instance.get_module_instance(
                module_name, current_session_id, project_name
            )
            
            if not module_instance:
                 return jsonify({"status": "error", "message": f"Module {module_name} not found"})

            logger.info(f"Executing module {module_name} with params: {params}")
            result = module_instance.run(params)

            status = result.get('status', 'error')
            message = result.get('message', 'Module execution failed.')
            raw_output = result.get('raw_output', '')
            structured_results = result.get('structured_results', {})
            
            # --- LLM ANALYSIS ---
            llm_analysis = "LLM analysis skipped."
            if Config.LLM_API_URL and status == 'success' and raw_output:
                llm_prompt = f"Analyze this security scan output:\n{raw_output}"
                llm_analysis = current_app.agent_instance._call_llm_api(llm_prompt)

            final_response = {
                'status': status,
                'message': message,
                'response_for_ui': _format_text_for_html_display(message),
                'user_command': command_string,
                'module_name': module_name,
                'target': params.get('target', 'N/A'),
                'structured_results': structured_results,
                'raw_output': _format_text_for_html_display(raw_output),
                'llm_analysis': llm_analysis
            }
            
            save_command_result(project_id, current_session_id, command_string, module_name, 
                                params.get('target', 'N/A'), status, message, structured_results, 
                                raw_output, llm_analysis)
            
            return jsonify(final_response)

        else:
            return jsonify({'status': 'error', 'message': f'Unknown command: {module_name}'})

    except Exception as e:
        logger.error(f"Error processing command: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/generate_project_report/<project_id>', methods=['GET'])
@login_required
def generate_project_report(project_id):
    user_id = session.get('user_id')
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, name FROM projects WHERE id = ? AND user_id = ?", (project_id, user_id))
    project = cursor.fetchone()
    if not project:
        return jsonify({'status': 'error', 'message': 'Project not found.'}), 404

    cursor.execute("SELECT user_command, llm_analysis FROM command_history WHERE project_id = ? ORDER BY timestamp ASC", (project_id,))
    history_entries = cursor.fetchall()

    if not history_entries:
        return jsonify({'status': 'success', 'project_name': project['name'], 'report_content': "No history found."})

    report_content = f"# Security Report: {project['name']}\n\n"
    for entry in history_entries:
        report_content += f"## Command: {entry['user_command']}\n\n"
        if entry['llm_analysis'] and entry['llm_analysis'] != 'N/A':
             # Corrected F-String Syntax Error
             clean_analysis = entry['llm_analysis'].replace('<br>', '\n')
             report_content += f"{clean_analysis}\n\n"
        else:
             report_content += "No analysis available.\n\n"

    return jsonify({
        'status': 'success',
        'project_name': project['name'],
        'report_content': report_content
    })

# --- 8. MAIN ENTRY POINT ---
if __name__ == '__main__':
    with app.app_context():
        init_db()
        app.agent_instance = AIAgent(modules_dict={
            'network_discovery': NetworkDiscoveryModule,
            'ip_scan': IPScanModule,
            'osint': OSINTModule
        })

    app.run(debug=True, host='0.0.0.0')