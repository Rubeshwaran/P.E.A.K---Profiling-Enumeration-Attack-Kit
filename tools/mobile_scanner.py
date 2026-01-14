import requests
import json
import os

class MobileScanner:
    def __init__(self):
        # Configure this in your config.py later if you want
        self.MOBSF_URL = "http://localhost:8000"
        self.API_KEY = "YOUR_API_KEY_HERE" 

    def upload_and_scan(self, file_path):
        """Uploads APK/IPA to MobSF and returns the scan report."""
        headers = {'Authorization': self.API_KEY}
        
        print(f"Uploading {file_path} to MobSF...")
        try:
            multipart_data = {
                'file': (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')
            }
        except FileNotFoundError:
            return {"error": f"File not found: {file_path}"}
            
        try:
            # 1. UPLOAD
            response = requests.post(f"{self.MOBSF_URL}/api/v1/upload", files=multipart_data, headers=headers)
            if response.status_code != 200:
                return {"error": f"Upload failed: {response.text}"}

            upload_data = response.json()
            scan_hash = upload_data['hash']
            scan_type = upload_data['scan_type']
            file_name = upload_data['file_name']

            # 2. SCAN
            print(f"Scanning {file_name} ({scan_hash})...")
            scan_data = {'scan_type': scan_type, 'file_name': file_name, 'hash': scan_hash}
            scan_response = requests.post(f"{self.MOBSF_URL}/api/v1/scan", data=scan_data, headers=headers)
            if scan_response.status_code != 200:
                return {"error": f"Scan failed: {scan_response.status_code}"}

            # 3. REPORT
            print("Fetching report...")
            report_headers = {'Authorization': self.API_KEY}
            report_data = {'hash': scan_hash}
            report_response = requests.post(f"{self.MOBSF_URL}/api/v1/report_json", data=report_data, headers=report_headers)

            if report_response.status_code != 200:
                return {"error": "Failed to retrieve report data."}

            report_json = report_response.json()

            # =======================================================
            # DEBUGGING: SAVE RAW REPORT TO FILE
            # This will create a file named 'mobsf_debug.json' in your project folder
            # =======================================================
            debug_filename = "mobsf_debug.json"
            with open(debug_filename, "w", encoding='utf-8') as f:
                json.dump(report_json, f, indent=4)
            print(f"DEBUG: Full raw report saved to {os.path.abspath(debug_filename)}")
            # =======================================================

            # Attempt to parse (Best Effort)
            final_score = "N/A"
            if 'security_score' in report_json:
                final_score = report_json['security_score']
            elif 'score' in report_json:
                final_score = report_json['score']
            elif 'average_cvss' in report_json:
                 final_score = int(float(report_json['average_cvss']) * 10)

            # Extract High Issues
            high_issues = []
            if 'code_analysis' in report_json and isinstance(report_json['code_analysis'], dict):
                for key, details in report_json['code_analysis'].items():
                    # Handle different code_analysis structures
                    if isinstance(details, dict):
                        meta = details.get('metadata', {})
                        if meta.get('severity', '').lower() in ['high', 'critical']:
                            high_issues.append({
                                'title': meta.get('title', key),
                                'description': meta.get('description', ''),
                                'severity': 'high'
                            })
            
            # Inject parsed data back
            report_json['security_score'] = final_score
            report_json['high_issues'] = high_issues

            return report_json

        except Exception as e:
            print(f"EXCEPTION: {str(e)}")
            return {"error": str(e)}