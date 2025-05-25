import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)
DB_NAME = 'livestock.db'

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS livestock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer TEXT NOT NULL,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            date TEXT NOT NULL,
            verified INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes ---
@app.route('/')
def index():
    conn = get_db_connection()
    total = conn.execute('SELECT SUM(quantity) FROM livestock').fetchone()[0] or 0
    verified = conn.execute('SELECT SUM(quantity) FROM livestock WHERE verified=1').fetchone()[0] or 0
    unverified = conn.execute('SELECT SUM(quantity) FROM livestock WHERE verified=0').fetchone()[0] or 0
    latest = conn.execute('SELECT * FROM livestock ORDER BY id DESC LIMIT 5').fetchall()
    conn.close()
    return render_template('index.html', total=total, verified=verified, unverified=unverified, latest=latest)

@app.route('/add', methods=['GET', 'POST'])
def add_livestock():
    if request.method == 'POST':
        farmer = request.form['farmer']
        ltype = request.form['type']
        quantity = request.form['quantity']
        date = request.form['date']
        if not (farmer and ltype and quantity and date):
            return render_template('add.html', error='All fields are required!')
        conn = get_db_connection()
        conn.execute('INSERT INTO livestock (farmer, type, quantity, date) VALUES (?, ?, ?, ?)',
                     (farmer, ltype, quantity, date))
        conn.commit()
        conn.close()
        return redirect(url_for('add_livestock', success=1))
    return render_template('add.html', success=request.args.get('success'))

@app.route('/verify', methods=['GET'])
def verify_list():
    conn = get_db_connection()
    entries = conn.execute('SELECT * FROM livestock').fetchall()
    conn.close()
    return render_template('verify.html', entries=entries)

@app.route('/verify_action', methods=['POST'])
def verify_action():
    action = request.form['action']
    entry_id = request.form['id']
    conn = get_db_connection()
    if action == 'verify':
        conn.execute('UPDATE livestock SET verified=1 WHERE id=?', (entry_id,))
    elif action == 'remove':
        conn.execute('DELETE FROM livestock WHERE id=?', (entry_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/livestock')
def api_livestock():
    # For AJAX table filtering
    q = request.args.get('q', '')
    conn = get_db_connection()
    if q:
        entries = conn.execute('SELECT * FROM livestock WHERE farmer LIKE ? OR type LIKE ?',
                               (f'%{q}%', f'%{q}%')).fetchall()
    else:
        entries = conn.execute('SELECT * FROM livestock').fetchall()
    conn.close()
    return jsonify([dict(row) for row in entries])

@app.route('/stats')
def stats():
    conn = get_db_connection()
    total = conn.execute('SELECT SUM(quantity) FROM livestock').fetchone()[0] or 0
    verified = conn.execute('SELECT SUM(quantity) FROM livestock WHERE verified=1').fetchone()[0] or 0
    unverified = conn.execute('SELECT SUM(quantity) FROM livestock WHERE verified=0').fetchone()[0] or 0
    type_counts = conn.execute('SELECT type, SUM(quantity) as qty FROM livestock GROUP BY type').fetchall()
    most_common = conn.execute('SELECT type FROM livestock GROUP BY type ORDER BY SUM(quantity) DESC LIMIT 1').fetchone()
    conn.close()
    return render_template('stats.html', total=total, verified=verified, unverified=unverified, type_counts=type_counts, most_common=most_common[0] if most_common else None)

@app.route('/api/type_distribution')
def api_type_distribution():
    conn = get_db_connection()
    type_counts = conn.execute('SELECT type, SUM(quantity) as qty FROM livestock GROUP BY type').fetchall()
    conn.close()
    return jsonify({row['type']: row['qty'] for row in type_counts})

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0') 