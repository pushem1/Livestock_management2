import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
DB_NAME = 'livestock.db'
socketio = SocketIO(app)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Create farmers table
    c.execute('''
        CREATE TABLE IF NOT EXISTS farmers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            rfid TEXT
        )
    ''')
    # Create livestock table if not exists
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
    # Add rfid column if missing
    c.execute("PRAGMA table_info(livestock)")
    columns = [col[1] for col in c.fetchall()]
    if 'rfid' not in columns:
        c.execute('ALTER TABLE livestock ADD COLUMN rfid TEXT')
    # Add farmer_id column if missing
    c.execute("PRAGMA table_info(livestock)")
    columns = [col[1] for col in c.fetchall()]
    if 'farmer_id' not in columns:
        c.execute('ALTER TABLE livestock ADD COLUMN farmer_id INTEGER')
    # Add rfid column to farmers if missing
    c.execute("PRAGMA table_info(farmers)")
    columns = [col[1] for col in c.fetchall()]
    if 'rfid' not in columns:
        c.execute('ALTER TABLE farmers ADD COLUMN rfid TEXT')
    conn.commit()
    conn.close()

# Helper: Add a farmer
def add_farmer(name):
    conn = get_db_connection()
    conn.execute('INSERT INTO farmers (name) VALUES (?)', (name,))
    conn.commit()
    conn.close()

# Helper: List all farmers
def list_farmers():
    conn = get_db_connection()
    farmers = conn.execute('SELECT * FROM farmers').fetchall()
    conn.close()
    return farmers

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
        ltype = request.form['type'].upper()  # Convert to uppercase for consistency
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
    entries = conn.execute('''
        SELECT livestock.*, farmers.name as farmer_name
        FROM livestock
        LEFT JOIN farmers ON livestock.farmer_id = farmers.id
    ''').fetchall()
    
    # Get summary with counts by type for each farmer (case-insensitive)
    summary = conn.execute('''
        SELECT 
            farmers.name,
            farmers.id,
            UPPER(livestock.type) as type,
            COUNT(livestock.id) as animal_count,
            SUM(livestock.quantity) as total_quantity
        FROM farmers
        LEFT JOIN livestock ON livestock.farmer_id = farmers.id
        GROUP BY farmers.id, UPPER(livestock.type)
        ORDER BY farmers.name, UPPER(livestock.type)
    ''').fetchall()
    
    # Organize summary data by farmer
    farmer_summary = {}
    for row in summary:
        farmer_name = row['name']
        if farmer_name not in farmer_summary:
            farmer_summary[farmer_name] = {
                'id': row['id'],
                'types': {},
                'total_animals': 0
            }
        if row['type']:
            # Convert type to title case for display
            display_type = row['type'].title()
            farmer_summary[farmer_name]['types'][display_type] = {
                'count': row['animal_count'],
                'quantity': row['total_quantity']
            }
            farmer_summary[farmer_name]['total_animals'] += row['total_quantity']
    
    conn.close()
    return render_template('verify.html', entries=entries, summary=farmer_summary)

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

@app.route('/api/rfid_scan', methods=['POST'])
def rfid_scan():
    data = request.get_json()
    rfid = data.get('rfid')
    conn = get_db_connection()
    # Check if RFID already exists
    exists = conn.execute('SELECT id FROM livestock WHERE rfid = ?', (rfid,)).fetchone()
    if not exists:
        # Insert with placeholder values
        conn.execute('INSERT INTO livestock (farmer, type, quantity, date, verified, rfid) VALUES (?, ?, ?, ?, ?, ?)',
                     ("RFID Scan", "Unknown", 1, "2024-01-01", 0, rfid))
        conn.commit()
    conn.close()
    socketio.emit('rfid_scanned', {'rfid': rfid})
    return jsonify({'status': 'success', 'rfid': rfid})

@app.route('/api/farmer_scan', methods=['POST'])
def farmer_scan():
    data = request.get_json()
    farmer_rfid = data.get('rfid')
    name = data.get('name', f"Farmer {farmer_rfid}")
    conn = get_db_connection()
    exists = conn.execute('SELECT id FROM farmers WHERE rfid = ?', (farmer_rfid,)).fetchone()
    if not exists:
        conn.execute('INSERT INTO farmers (name, rfid) VALUES (?, ?)', (name, farmer_rfid))
        conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'name': name})

@app.route('/api/associate_livestock', methods=['POST'])
def associate_livestock():
    data = request.get_json()
    livestock_rfid = data.get('livestock_rfid')
    farmer_rfid = data.get('farmer_rfid')
    farmer_name = data.get('farmer_name', f"Farmer {farmer_rfid}")
    livestock_type = data.get('type', 'Unknown').upper()  # Convert to uppercase for consistency

    conn = get_db_connection()
    # Ensure farmer exists (using rfid as unique identifier)
    farmer = conn.execute('SELECT id FROM farmers WHERE rfid = ?', (farmer_rfid,)).fetchone()
    if not farmer:
        conn.execute('INSERT INTO farmers (name, rfid) VALUES (?, ?)', (farmer_name, farmer_rfid))
        conn.commit()
        farmer = conn.execute('SELECT id FROM farmers WHERE rfid = ?', (farmer_rfid,)).fetchone()
    farmer_id = farmer['id']

    # Ensure livestock exists and associate with farmer
    exists = conn.execute('SELECT id FROM livestock WHERE rfid = ?', (livestock_rfid,)).fetchone()
    if not exists:
        conn.execute('INSERT INTO livestock (farmer, type, quantity, date, verified, rfid, farmer_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (farmer_name, livestock_type, 1, "2024-01-01", 0, livestock_rfid, farmer_id))
        conn.commit()
    else:
        # Optionally update the farmer_id and type if livestock already exists
        conn.execute('UPDATE livestock SET farmer_id = ?, farmer = ?, type = ? WHERE rfid = ?', (farmer_id, farmer_name, livestock_type, livestock_rfid))
        conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'livestock_rfid': livestock_rfid, 'farmer_id': farmer_id})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0') 