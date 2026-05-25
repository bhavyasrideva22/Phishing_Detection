import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = 'phishing_detector.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT,
            result TEXT,
            threat_level TEXT,
            risk_score INTEGER,
            scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, email=''):
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, hash_password(password), email)
        )
        conn.commit()
        return {'success': True}
    except sqlite3.IntegrityError:
        return {'success': False, 'message': 'Username already exists'}
    finally:
        conn.close()

def login_user(username, password):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        'SELECT * FROM users WHERE username=? AND password_hash=?',
        (username, hash_password(password))
    )
    user = c.fetchone()
    if user:
        c.execute('UPDATE users SET last_login=? WHERE id=?',
                  (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
        conn.commit()
        conn.close()
        return dict(user)
    conn.close()
    return None

def save_scan(user_id, content, result, threat_level, risk_score):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        'INSERT INTO scans (user_id, content, result, threat_level, risk_score) VALUES (?, ?, ?, ?, ?)',
        (user_id, content, result, threat_level, risk_score)
    )
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_user_scans(user_id, limit=50):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        'SELECT id, threat_level, risk_score, scanned_at, content FROM scans WHERE user_id=? ORDER BY scanned_at DESC LIMIT ?',
        (user_id, limit)
    )
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        d = dict(row)
        d['content_preview'] = d.get('content', '')[:120] + '...' if d.get('content') and len(d.get('content','')) > 120 else d.get('content','')
        result.append(d)
    return result

def get_scan_by_id(scan_id, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id=? AND user_id=?', (scan_id, user_id))
    row = c.fetchone()
    conn.close()
    if row:
        import json
        d = dict(row)
        try:
            d['result_data'] = json.loads(d['result'])
        except:
            d['result_data'] = {}
        return d
    return None

def delete_scan(scan_id, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM scans WHERE id=? AND user_id=?', (scan_id, user_id))
    deleted = c.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def clear_user_scans(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM scans WHERE user_id=?', (user_id,))
    deleted_count = c.rowcount
    conn.commit()
    conn.close()
    return deleted_count
