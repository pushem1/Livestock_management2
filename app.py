import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from pymongo import MongoClient, errors
from bson.objectid import ObjectId
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import json

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow all origins for ESP32

# --- MongoDB Setup and Utilities ---
def get_db():
    """Establish and return the MongoDB database connection."""
    MONGODB_URI = os.getenv('MONGODB_URI')
    if not MONGODB_URI:
        raise ValueError("MONGODB_URI environment variable is not set!")
    try:
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        db = client.get_default_database()
        return db
    except errors.ServerSelectionTimeoutError as e:
        raise ConnectionError(f"Could not connect to MongoDB: {e}")

db = get_db()
users_col = db['users']
types_col = db['types']
animals_col = db['animals']
devices_col = db['devices']  # New collection for ESP32 devices

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            current_user = users_col.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            current_user = users_col.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user or current_user['role'] != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Dashboard Routes ---
@app.route('/')
def index():
    """Home page - redirects to appropriate dashboard based on user role."""
    token = session.get('token')
    if not token:
        return redirect(url_for('login_page'))
    
    try:
        data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        user = users_col.find_one({'_id': ObjectId(data['user_id'])})
        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    except:
        return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    """Login page."""
    return render_template('login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard(current_user):
    """Admin dashboard."""
    # Color mapping for animal types (original green palette)
    green_palette = [
        '#388e3c', '#43a047', '#66bb6a', '#81c784', '#a5d6a7', '#c8e6c9', '#e8f5e9'
    ]
    animal_types = list({(animal.get('type') if not hasattr(animal.get('type'), 'binary') and not hasattr(animal.get('type'), 'generation_time') else types_col.find_one({'_id': animal.get('type')})['name']) for animal in animals_col.find()})
    animal_types = [str(t).title().strip() for t in animal_types]
    animal_type_colors = {t: green_palette[i % len(green_palette)] for i, t in enumerate(animal_types)}
    # Get statistics
    stats = {
        'total_users': users_col.count_documents({}),
        'total_animals': animals_col.count_documents({}),
        'total_devices': devices_col.count_documents({}),
        'active_devices': devices_col.count_documents({'status': 'active'}),
        'recent_animals': [],  # Will fill below
        'recent_users': list(users_col.find().sort('created_at', -1).limit(5))
    }
    # Prepare animal type counts for chart (normalize to title case)
    animal_type_counts = {}
    for animal in animals_col.find():
        t = animal.get('type')
        if hasattr(t, 'binary') or hasattr(t, 'generation_time'):
            type_doc = types_col.find_one({'_id': t})
            type_name = type_doc['name'] if type_doc else str(t)
        else:
            type_name = str(t)
        type_name = type_name.title().strip()
        animal_type_counts[type_name] = animal_type_counts.get(type_name, 0) + 1
    # Prepare recent animals with rfid and type_name (normalize type_name)
    recent_animals = []
    for animal in animals_col.find().sort('created_at', -1).limit(5):
        t = animal.get('type')
        if hasattr(t, 'binary') or hasattr(t, 'generation_time'):
            type_doc = types_col.find_one({'_id': t})
            type_name = type_doc['name'] if type_doc else str(t)
        elif isinstance(t, dict) and 'name' in t:
            type_name = t['name']
        else:
            type_name = str(t)
        type_name = type_name.title().strip()
        recent_animals.append({
            'rfid': animal.get('rfid'),
            'type_name': type_name,
            'status': animal.get('status'),
            'created_at': animal.get('created_at') or animal.get('createdAt')
        })
    stats['recent_animals'] = recent_animals
    # Prepare farmers list with animal counts
    farmers = []
    for user in users_col.find():
        animal_count = animals_col.count_documents({'owner': user['_id']})
        created_at = user.get('created_at') or user.get('createdAt') or None
        farmers.append({
            'name': user.get('name'),
            'email': user.get('email'),
            'role': user.get('role'),
            'animal_count': animal_count,
            'created_at': created_at
        })
    return render_template('admin/dashboard.html', stats=stats, animal_type_counts=animal_type_counts, animal_type_colors=animal_type_colors, farmers=farmers)

@app.route('/user/dashboard')
@login_required
def user_dashboard(current_user):
    """User dashboard."""
    # Get user's animals
    animals = list(animals_col.find({'owner': current_user['_id']}))
    # Get user's devices (if any)
    devices = list(devices_col.find({'owner': current_user['_id']}))
    # Prepare animal type counts for chart
    animal_type_counts = {}
    for animal in animals:
        t = animal.get('type')
        # If type is an ObjectId, get the type name
        if hasattr(t, 'binary') or hasattr(t, 'generation_time'):
            type_doc = types_col.find_one({'_id': t})
            type_name = type_doc['name'] if type_doc else str(t)
        else:
            type_name = str(t)
        animal_type_counts[type_name] = animal_type_counts.get(type_name, 0) + 1
    return render_template('user/dashboard.html', animals=animals, devices=devices, animal_type_counts=animal_type_counts)

# --- Admin Management Routes ---
@app.route('/admin/users')
@admin_required
def admin_users(current_user):
    users = []
    for user in users_col.find():
        animal_count = animals_col.count_documents({'owner': user['_id']})
        users.append({
            'name': user.get('name'),
            'email': user.get('email'),
            'role': user.get('role'),
            'animal_count': animal_count,
            'created_at': user.get('created_at') or user.get('createdAt')
        })
    return render_template('admin/users.html', users=users)

@app.route('/admin/devices')
@admin_required
def admin_devices(current_user):
    devices = []
    for device in devices_col.find():
        # Get owner name if assigned
        owner_name = ''
        owner_id = device.get('owner')
        if owner_id:
            owner = users_col.find_one({'_id': owner_id})
            owner_name = owner['name'] if owner else 'Unknown'
        devices.append({
            'device_id': device.get('device_id'),
            'status': device.get('status'),
            'owner_name': owner_name,
            'last_seen': device.get('last_seen'),
            'created_at': device.get('created_at') or device.get('createdAt')
        })
    return render_template('admin/devices.html', devices=devices)

@app.route('/admin/animals')
@admin_required
def admin_animals(current_user):
    animals = []
    for animal in animals_col.find():
        # Get type name
        t = animal.get('type')
        if hasattr(t, 'binary') or hasattr(t, 'generation_time'):
            type_doc = types_col.find_one({'_id': t})
            type_name = type_doc['name'] if type_doc else str(t)
        else:
            type_name = str(t)
        # Get owner name
        owner = users_col.find_one({'_id': animal.get('owner')})
        owner_name = owner['name'] if owner else 'Unknown'
        animals.append({
            'name': animal.get('name'),
            'rfid': animal.get('rfid'),
            'type_name': type_name,
            'owner_name': owner_name,
            'status': animal.get('status'),
            'birthDate': animal.get('birthDate'),
            'updated_at': animal.get('updated_at') or animal.get('updatedAt')
        })
    return render_template('admin/animals.html', animals=animals)

# --- User Management API ---
@app.route('/api/users', methods=['GET'])
@admin_required
def get_users(current_user):
    """Get all users (admin only)."""
    users = list(users_col.find())
    return jsonify([{
        'id': str(u['_id']),
        'name': u['name'],
        'email': u['email'],
        'role': u['role'],
        'created_at': u['created_at']
    } for u in users])

@app.route('/api/users/<user_id>', methods=['PUT'])
@admin_required
def update_user(current_user, user_id):
    """Update user (admin only)."""
    data = request.get_json()
    update_data = {}
    
    if 'name' in data:
        update_data['name'] = data['name']
    if 'role' in data:
        update_data['role'] = data['role']
    
    if update_data:
        update_data['updated_at'] = datetime.utcnow()
        users_col.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        return jsonify({'message': 'User updated successfully'})
    return jsonify({'error': 'No fields to update'}), 400

@app.route('/api/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(current_user, user_id):
    """Delete user (admin only)."""
    if str(current_user['_id']) == user_id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    users_col.delete_one({'_id': ObjectId(user_id)})
    return jsonify({'message': 'User deleted successfully'})

# --- User Profile API ---
@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile(current_user):
    """Get current user's profile."""
    return jsonify({
        'id': str(current_user['_id']),
        'name': current_user['name'],
        'email': current_user['email'],
        'role': current_user['role']
    })

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile(current_user):
    """Update current user's profile."""
    data = request.get_json()
    update_data = {}
    
    if 'name' in data:
        update_data['name'] = data['name']
    if 'password' in data:
        update_data['password'] = generate_password_hash(data['password'])
    
    if update_data:
        update_data['updated_at'] = datetime.utcnow()
        users_col.update_one(
            {'_id': current_user['_id']},
            {'$set': update_data}
        )
        return jsonify({'message': 'Profile updated successfully'})
    return jsonify({'error': 'No fields to update'}), 400

# --- Device Management API ---
@app.route('/api/devices', methods=['GET'])
@admin_required
def get_devices(current_user):
    """Get all devices (admin only)."""
    devices = list(devices_col.find())
    return jsonify([{
        'id': str(d['_id']),
        'device_id': d['device_id'],
        'status': d['status'],
        'last_seen': d['last_seen'],
        'owner': str(d.get('owner', ''))
    } for d in devices])

@app.route('/api/devices/<device_id>', methods=['PUT'])
@admin_required
def update_device(current_user, device_id):
    """Update device (admin only)."""
    data = request.get_json()
    update_data = {}
    
    if 'status' in data:
        update_data['status'] = data['status']
    if 'owner' in data:
        update_data['owner'] = ObjectId(data['owner'])
    
    if update_data:
        update_data['updated_at'] = datetime.utcnow()
        devices_col.update_one(
            {'_id': ObjectId(device_id)},
            {'$set': update_data}
        )
        return jsonify({'message': 'Device updated successfully'})
    return jsonify({'error': 'No fields to update'}), 400

# --- WebSocket Events ---
@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connections."""
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnections."""
    print('Client disconnected')

@socketio.on('register_device')
def handle_device_registration(data):
    """Register a new ESP32 device."""
    try:
        device_id = data.get('device_id')
        if not device_id:
            emit('error', {'message': 'Device ID required'})
            return

        # Check if device already exists
        existing_device = devices_col.find_one({'device_id': device_id})
        if existing_device:
            emit('device_registered', {
                'status': 'existing',
                'device_id': device_id
            })
        else:
            # Register new device
            device = {
                'device_id': device_id,
                'status': 'active',
                'last_seen': datetime.utcnow(),
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            devices_col.insert_one(device)
            emit('device_registered', {
                'status': 'new',
                'device_id': device_id
            })
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('rfid_scan')
def handle_rfid_scan(data):
    """Handle RFID scans from ESP32."""
    try:
        rfid = data.get('rfid')
        device_id = data.get('device_id')
        
        if not rfid or not device_id:
            emit('error', {'message': 'RFID and device_id required'})
            return

        # Update device last seen
        devices_col.update_one(
            {'device_id': device_id},
            {'$set': {'last_seen': datetime.utcnow()}}
        )

        # Find animal with this RFID
        animal = animals_col.find_one({'rfid': rfid})
        if animal:
            # Emit to all clients
            emit('animal_found', {
                'rfid': rfid,
                'animal': {
                    'id': str(animal['_id']),
                    'name': animal['name'],
                    'type': str(animal['type']),
                    'status': animal['status']
                }
            }, broadcast=True)
        else:
            emit('animal_not_found', {'rfid': rfid})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('update_animal_status')
def handle_status_update(data):
    """Handle animal status updates from ESP32."""
    try:
        rfid = data.get('rfid')
        status = data.get('status')
        device_id = data.get('device_id')

        if not all([rfid, status, device_id]):
            emit('error', {'message': 'RFID, status, and device_id required'})
            return

        # Update animal status
        result = animals_col.update_one(
            {'rfid': rfid},
            {'$set': {
                'status': status,
                'updated_at': datetime.utcnow()
            }}
        )

        if result.modified_count > 0:
            emit('status_updated', {
                'rfid': rfid,
                'status': status
            }, broadcast=True)
        else:
            emit('error', {'message': 'Animal not found'})
    except Exception as e:
        emit('error', {'message': str(e)})

# --- ESP32 API Endpoints ---
@app.route('/api/device/register', methods=['POST'])
def register_device():
    """Register a new ESP32 device."""
    data = request.get_json()
    device_id = data.get('device_id')
    
    if not device_id:
        return jsonify({'error': 'Device ID required'}), 400

    try:
        device = {
            'device_id': device_id,
            'status': 'active',
            'last_seen': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        devices_col.insert_one(device)
        return jsonify({'message': 'Device registered successfully'}), 201
    except errors.DuplicateKeyError:
        return jsonify({'message': 'Device already registered'}), 200

@app.route('/api/device/heartbeat', methods=['POST'])
def device_heartbeat():
    """Update device last seen timestamp."""
    data = request.get_json()
    device_id = data.get('device_id')
    
    if not device_id:
        return jsonify({'error': 'Device ID required'}), 400

    devices_col.update_one(
        {'device_id': device_id},
        {'$set': {'last_seen': datetime.utcnow()}}
    )
    return jsonify({'message': 'Heartbeat received'})

@app.route('/api/animal/scan', methods=['POST'])
def scan_animal():
    """Handle RFID scan from ESP32."""
    data = request.get_json()
    rfid = data.get('rfid')
    device_id = data.get('device_id')
    
    if not rfid or not device_id:
        return jsonify({'error': 'RFID and device_id required'}), 400

    animal = animals_col.find_one({'rfid': rfid})
    if animal:
        return jsonify({
            'found': True,
            'animal': {
                'id': str(animal['_id']),
                'name': animal['name'],
                'type': str(animal['type']),
                'status': animal['status']
            }
        })
    return jsonify({'found': False})

# --- User Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check if email already exists
        if users_col.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create new user
        user = {
            'name': data['name'],
            'email': data['email'],
            'password': generate_password_hash(data['password']),
            'role': 'user',  # Default role
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        result = users_col.insert_one(user)
        
        # Generate token for immediate login
        token = jwt.encode(
            {'user_id': str(result.inserted_id), 'exp': datetime.utcnow() + timedelta(days=1)},
            app.secret_key
        )
        
        return jsonify({
            'message': 'Registration successful',
            'token': token
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not all(k in data for k in ['email', 'password']):
        return jsonify({'error': 'Missing email or password'}), 400
    
    user = users_col.find_one({'email': data['email']})
    if user and check_password_hash(user['password'], data['password']):
        token = jwt.encode(
            {'user_id': str(user['_id']), 'exp': datetime.utcnow() + timedelta(days=1)},
            app.secret_key
        )
        session['token'] = token
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email'],
                'role': user['role']
            }
        })
    return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """Handle user logout."""
    session.pop('token', None)
    return jsonify({'success': True})

# --- Type Routes ---
@app.route('/types', methods=['GET'])
def get_types():
    types = list(types_col.find())
    return jsonify([{
        'id': str(t['_id']),
        'name': t['name'],
        'slug': t['slug']
    } for t in types])

@app.route('/types', methods=['POST'])
@login_required
def create_type(current_user):
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    if not data.get('name'):
        return jsonify({'error': 'Name is required'}), 400
    
    type_doc = {
        'name': data['name'],
        'slug': data['name'].lower().replace(' ', '-'),
        'createdAt': datetime.utcnow(),
        'updatedAt': datetime.utcnow(),
        '__v': 0
    }
    
    try:
        result = types_col.insert_one(type_doc)
        return jsonify({'message': 'Type created', 'id': str(result.inserted_id)}), 201
    except errors.DuplicateKeyError:
        return jsonify({'error': 'Type name already exists'}), 400

# --- Animal Routes ---
@app.route('/animals', methods=['GET'])
@login_required
def get_animals(current_user):
    query = {}
    if current_user['role'] != 'admin':
        query['owner'] = current_user['_id']
    
    animals = list(animals_col.find(query))
    # Populate type and owner information
    for animal in animals:
        animal['type'] = types_col.find_one({'_id': animal['type']})
        animal['owner'] = users_col.find_one({'_id': animal['owner']})
        animal['id'] = str(animal['_id'])
    
    return jsonify(animals)

@app.route('/animals', methods=['POST'])
@login_required
def create_animal(current_user):
    data = request.get_json()
    required_fields = ['rfid', 'name', 'type', 'age', 'birthDate', 'gender']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Verify type exists
    if not types_col.find_one({'_id': ObjectId(data['type'])}):
        return jsonify({'error': 'Invalid animal type'}), 400
    
    animal = {
        'rfid': data['rfid'],
        'name': data['name'],
        'type': ObjectId(data['type']),
        'slug': data['type'],
        'age': data['age'],
        'birthDate': datetime.fromisoformat(data['birthDate'].replace('Z', '+00:00')),
        'gender': data['gender'],
        'vaccin': data.get('vaccin', False),
        'owner': current_user['_id'],
        'status': 'pending',
        'createdAt': datetime.utcnow(),
        'updatedAt': datetime.utcnow(),
        '__v': 0
    }
    
    try:
        result = animals_col.insert_one(animal)
        return jsonify({'message': 'Animal created', 'id': str(result.inserted_id)}), 201
    except errors.DuplicateKeyError:
        return jsonify({'error': 'RFID already exists'}), 400

@app.route('/animals/<animal_id>', methods=['PUT'])
@login_required
def update_animal(current_user, animal_id):
    animal = animals_col.find_one({'_id': ObjectId(animal_id)})
    if not animal:
        return jsonify({'error': 'Animal not found'}), 404
    
    if current_user['role'] != 'admin' and str(animal['owner']) != str(current_user['_id']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    update_data = {
        'updatedAt': datetime.utcnow()
    }
    
    # Update only provided fields
    for field in ['name', 'age', 'birthDate', 'gender', 'vaccin', 'status']:
        if field in data:
            if field == 'birthDate':
                update_data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
            else:
                update_data[field] = data[field]
    
    animals_col.update_one(
        {'_id': ObjectId(animal_id)},
        {'$set': update_data}
    )
    
    return jsonify({'message': 'Animal updated successfully'})

@app.route('/animals/<animal_id>', methods=['DELETE'])
@login_required
def delete_animal(current_user, animal_id):
    animal = animals_col.find_one({'_id': ObjectId(animal_id)})
    if not animal:
        return jsonify({'error': 'Animal not found'}), 404
    
    if current_user['role'] != 'admin' and str(animal['owner']) != str(current_user['_id']):
        return jsonify({'error': 'Unauthorized'}), 403
    
    animals_col.delete_one({'_id': ObjectId(animal_id)})
    return jsonify({'message': 'Animal deleted successfully'})

# --- Test route ---
@app.route('/test_env')
def test_env():
    try:
        client_info = db.client.server_info()
        status = 'connected'
    except Exception as e:
        status = f'disconnected: {e}'
    return jsonify({
        'mongodb_uri_set': bool(os.getenv('MONGODB_URI')),
        'connection_status': status
    })

# Add this after the app initialization and before the routes
@app.context_processor
def inject_user():
    """Make current_user available in all templates."""
    try:
        token = session.get('token')
        if token:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            user = users_col.find_one({'_id': ObjectId(data['user_id'])})
            if user:
                return {'current_user': user}
    except:
        pass
    return {'current_user': None}

@app.route('/profile')
@login_required
def profile_page(current_user):
    return render_template('profile.html')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0') 