from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import os
import json
from datetime import datetime
from database import init_db, register_user, login_user, save_scan, get_user_scans, get_scan_by_id, delete_scan, clear_user_scans
from parser_module import parse_email_content
from scanner import analyze_urls, calculate_risk_score
from model import predict_phishing
from report_generator import generate_report
import base64

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phishdetect_secret_2024")
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'eml', 'txt', 'msg'}

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return "Running"

@app.route('/dashboard')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        user = login_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    email = data.get('email', '').strip()
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})
    result = register_user(username, password, email)
    if result['success']:
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': result['message']})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/scan', methods=['POST'])
def scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    input_type = request.form.get('input_type', 'text')
    email_content = ""
    image_data = None

    if input_type == 'text':
        email_content = request.form.get('content', '')
    elif input_type == 'file':
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = file.filename.lower()
            if filename.endswith(('.png', '.jpg', '.jpeg', '.gif')):
                # Image file - read as base64 for display, extract text if possible
                image_bytes = file.read()
                image_data = base64.b64encode(image_bytes).decode('utf-8')
                ext = filename.rsplit('.', 1)[1]
                email_content = f"[Image uploaded: {file.filename}] Image analysis: suspicious content detected in uploaded image."
                try:
                    import pytesseract
                    from PIL import Image
                    import io
                    img = Image.open(io.BytesIO(image_bytes))
                    email_content = pytesseract.image_to_string(img)
                    if not email_content.strip():
                        email_content = f"[Image: {file.filename}] No text could be extracted."
                except:
                    email_content = f"[Image uploaded: {file.filename}] Image file received. Manual analysis required."
            else:
                email_content = file.read().decode('utf-8', errors='ignore')
        else:
            return jsonify({'error': 'Invalid file type'}), 400
    elif input_type == 'email_paste':
        email_content = request.form.get('content', '')

    if not email_content and not image_data:
        return jsonify({'error': 'No content to analyze'}), 400

    # Parse content
    parsed = parse_email_content(email_content)

    # Scan URLs
    url_results = analyze_urls(parsed['urls'])

    # ML Prediction
    ml_result = predict_phishing(email_content)

    # Calculate risk score
    risk_data = calculate_risk_score(parsed, url_results, ml_result)

    # Determine threat level
    score = risk_data['score']
    if score <= 30:
        threat_level = "SAFE"
        threat_class = "safe"
    elif score <= 60:
        threat_level = "SUSPICIOUS"
        threat_class = "suspicious"
    else:
        threat_level = "PHISHING"
        threat_class = "phishing"

    result = {
        'threat_level': threat_level,
        'threat_class': threat_class,
        'risk_score': score,
        'ml_prediction': ml_result['prediction'],
        'ml_confidence': ml_result['confidence'],
        'urls': url_results,
        'keywords_found': parsed['keywords_found'],
        'indicators': risk_data['indicators'],
        'email_addresses': parsed['email_addresses'],
        'input_type': input_type,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # Save to database
    scan_id = save_scan(
        user_id=session['user_id'],
        content=email_content[:2000],
        result=json.dumps(result),
        threat_level=threat_level,
        risk_score=score
    )
    result['scan_id'] = scan_id

    return jsonify(result)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    scans = get_user_scans(session['user_id'])
    return jsonify(scans)

@app.route('/scan/<int:scan_id>', methods=['GET', 'DELETE'])
def scan_detail(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if request.method == 'DELETE':
        if delete_scan(scan_id, session['user_id']):
            return jsonify({'success': True})
        return jsonify({'error': 'Scan not found'}), 404
    scan = get_scan_by_id(scan_id, session['user_id'])
    if scan:
        return jsonify(scan)
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/report/<int:scan_id>')
def download_report(scan_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    scan = get_scan_by_id(scan_id, session['user_id'])
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    report_path = generate_report(scan, session['username'])
    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"phish_report_{scan_id}.txt",
        mimetype='text/plain; charset=utf-8'
    )

@app.route('/history/clear', methods=['DELETE'])
def clear_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    count = clear_user_scans(session['user_id'])
    return jsonify({'success': True, 'deleted': count})

@app.route('/stats')
def stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    scans = get_user_scans(session['user_id'])
    total = len(scans)
    phishing = sum(1 for s in scans if s['threat_level'] == 'PHISHING')
    suspicious = sum(1 for s in scans if s['threat_level'] == 'SUSPICIOUS')
    safe = sum(1 for s in scans if s['threat_level'] == 'SAFE')
    return jsonify({
        'total': total,
        'phishing': phishing,
        'suspicious': suspicious,
        'safe': safe
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
