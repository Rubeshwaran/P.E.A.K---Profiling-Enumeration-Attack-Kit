import json
import os
import datetime
import webbrowser

# Configuration
SESSION_FILE = "current_session_data.json"
REPORT_DIR = "reports"

def generate_static_report():
    if not os.path.exists(SESSION_FILE):
        return {"status": "error", "message": "No session data found. Run some agents first!"}

    # 1. Load Data
    with open(SESSION_FILE, "r") as f:
        data = json.load(f)

    # 2. HTML Template (Professional Dark Theme)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PEAK Security Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
            .container {{ max-width: 900px; margin: auto; background: #1e293b; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
            h1 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 10px; }}
            .entry {{ margin-bottom: 25px; border: 1px solid #334155; border-radius: 5px; overflow: hidden; }}
            .entry-header {{ background: #334155; padding: 10px 15px; display: flex; justify-content: space-between; font-weight: bold; color: #fff; }}
            .entry-cmd {{ font-family: monospace; color: #94a3b8; font-size: 0.9em; padding: 5px 15px; background: #263345; border-bottom: 1px solid #334155; }}
            pre {{ background: #0f172a; padding: 15px; margin: 0; overflow-x: auto; color: #a5b4fc; font-family: 'Consolas', monospace; white-space: pre-wrap; }}
            .footer {{ margin-top: 30px; text-align: center; color: #64748b; font-size: 0.8em; }}
            .badge {{ background: #0ea5e9; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>⛰️ PEAK Security Assessment</h1>
            <p><strong>Generated:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Total Actions:</strong> {len(data)}</p>
            <hr style="border-color: #334155">

            {''.join([f'''
            <div class="entry">
                <div class="entry-header">
                    <span><span class="badge">{item['agent'].upper()}</span> &nbsp; {item['timestamp']}</span>
                </div>
                <div class="entry-cmd">CMD: {item['command']}</div>
                <pre>{item['output'].replace("<", "&lt;").replace(">", "&gt;")}</pre>
            </div>
            ''' for item in data])}
            
            <div class="footer">
                PEAK Intelligent Agent Framework &copy; 2026
            </div>
        </div>
    </body>
    </html>
    """

    # 3. Save File
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)
        
    filename = f"PEAK_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return {"status": "success", "file": filepath}

if __name__ == "__main__":
    result = generate_static_report()
    if result["status"] == "success":
        print(f"REPORT GENERATED: {result['file']}")
        # Optional: Auto-open in browser
        # webbrowser.open("file://" + os.path.abspath(result['file']))
    else:
        print(f"ERROR: {result['message']}")