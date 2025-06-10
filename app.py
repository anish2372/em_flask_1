from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import paho.mqtt.client as mqtt
from threading import Thread
import json

from flask_socketio import SocketIO, emit

# Get absolute path to devices.db
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICES_DB_PATH = os.path.join(os.path.dirname(__file__), 'devices.db')
print("USING DEVICES DB:", DEVICES_DB_PATH)
conn = sqlite3.connect(DEVICES_DB_PATH)
c = conn.cursor()
USERS_DB_PATH = os.path.join(BASE_DIR, "users.db")


app = Flask(__name__)

app.secret_key = 'your-secret-key'  # Change this for production
socketio = SocketIO(app)


MQTT_BROKER = "mqtt.eclipseprojects.io"
MQTT_PORT = 1883
# These are now dynamic per device, but kept for reference if a global topic is ever needed
# MQTT_TOPIC_REQUEST = "{mac}/request"
# MQTT_TOPIC_RESPONSE = "{mac}/response"

mqtt_client = mqtt.Client(protocol=mqtt.MQTTv311)

# Dictionary to store the latest state for each device
device_states = {}

def on_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Connected to MQTT Broker.")
        # Subscribe to response topics for all registered devices
        conn = sqlite3.connect(DEVICES_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT device_key FROM devices")
        device_keys = [row[0] for row in c.fetchall()]
        conn.close()

        for key in device_keys:
            topic = f"{key}/response"
            client.subscribe(topic)
            print(f"Subscribed to {topic}")
    else:
        print(f"❌ Failed to connect, reason code: {rc}")
        
def on_mqtt_message(client, userdata, msg):
    print(f"📩 Message received on {msg.topic}: {msg.payload.decode()}")
    try:
        data = json.loads(msg.payload.decode())
        device_key = msg.topic.split('/')[0]
        
        # Store the latest response for the device
        device_states[device_key] = data  
        
        # Emit data to client via SocketIO (if real-time updates are needed beyond page load)
        socketio.emit('device_data', {
            'device_key': device_key,
            'data': data
        }, namespace='/device')
        
        print(f"Updated state for device {device_key}: {data}")
    except Exception as e:
        print(f"❌ Failed to parse message from {msg.topic}: {e}")

mqtt_client.on_connect = on_mqtt_connect
mqtt_client.on_message = on_mqtt_message
mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)

mqtt_thread = Thread(target=mqtt_client.loop_forever)
mqtt_thread.daemon = True
mqtt_thread.start()


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(USERS_DB_PATH)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (username, generate_password_hash(password)))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(USERS_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password"

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DEVICES_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT device_key, ssid, wifi_password, device_name FROM devices")
    devices = c.fetchall()
    conn.close()

    return render_template('dashboard.html', username=session['username'], devices=devices)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/send')
def sender():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DEVICES_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT device_key, COALESCE(device_name, '') as device_name FROM devices")
    devices = c.fetchall()
    conn.close()

    return render_template('sender.html', devices=devices)


@app.route('/receive')
def receiver():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DEVICES_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT device_key, COALESCE(device_name, '') as device_name FROM devices")
    devices = c.fetchall()
    conn.close()

    return render_template('receiver.html', devices=devices)


@app.route('/add-device', methods=['GET', 'POST'])
def add_device():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        device_key = request.form['device_key']
        ssid = request.form['ssid']
        wifi_password = request.form['wifi_password']
        device_name = request.form.get('device_name', 'Unnamed Device').strip() # Get device name

        if len(device_key) != 16:
            return "Device key must be 16 characters long."

        try:
            conn = sqlite3.connect(DEVICES_DB_PATH)
            c = conn.cursor()
            c.execute(
                "INSERT INTO devices (device_key, ssid, wifi_password, device_name) VALUES (?, ?, ?, ?)",
                (device_key, ssid, wifi_password, device_name)
            )
            conn.commit()
            conn.close()
            
            # After adding, subscribe to its MQTT topic
            mqtt_client.subscribe(f"{device_key}/response")
            print(f"Subscribed to new device topic: {device_key}/response")

            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            return "Device with this key is already registered."

    conn = sqlite3.connect(DEVICES_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT device_key, COALESCE(device_name, '') as device_name FROM devices")
    devices = c.fetchall()
    conn.close()

    return render_template('add_device.html', devices=devices)


@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin123':
            session['admin'] = True
            return redirect(url_for('view_devices'))
        else:
            return "Invalid admin credentials"
    return render_template('admin_login.html')


@app.route('/view-devices')
def view_devices():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    conn = sqlite3.connect(DEVICES_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT device_key, ssid, wifi_password, device_name FROM devices")
    devices = c.fetchall()
    conn.close()
    
    return render_template('view_devices.html', devices=devices)
    

@app.route('/delete-device/<key>', methods=['POST'])
def delete_device(key):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DEVICES_DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM devices WHERE device_key = ?', (key,))
    conn.commit()
    conn.close()
    
    # Unsubscribe from MQTT topic for the deleted device
    mqtt_client.unsubscribe(f"{key}/response")
    print(f"Unsubscribed from deleted device topic: {key}/response")
    
    # Remove from device_states if present
    if key in device_states:
        del device_states[key]

    return redirect(url_for('view_devices'))
    
    
@app.route('/device/<device_key>', methods=['GET', 'POST'])
def device_page(device_key):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DEVICES_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Update device name if POST
    if request.method == 'POST':
        new_name = request.form.get('device_name', '').strip()
        c.execute("UPDATE devices SET device_name = ? WHERE device_key = ?", (new_name, device_key))
        conn.commit()

    # Fetch the device info
    c.execute("SELECT * FROM devices WHERE device_key = ?", (device_key,))
    device = c.fetchone()

    # Sidebar devices
    c.execute("SELECT device_key, COALESCE(device_name, '') as device_name FROM devices")
    devices = c.fetchall()
    conn.close()

    if not device:
        return "Device not found", 404

    # Get last known response for this specific device
    last_state = device_states.get(device_key, {}) # Provide an empty dict if no state is found

    # Determine auto mode based on the device's state (register 91)
    # Default to True if not in last_state, assuming auto is default or preferred
    is_auto_mode = last_state.get(91, 1) == 1 

    # Publish MQTT request for initial data when the page loads
    # This will trigger the ESP32 to send its current state
    mqtt_payload = json.dumps({
        "request_full_state": 1 # Request all relevant registers/state
    })
    mqtt_client.publish(f"{device_key}/request", mqtt_payload)
    print(f"Requested full state from device {device_key}")

    return render_template("device_page.html", 
        device=device, 
        devices=devices, 
        last_state=last_state,
        isAutoMode=is_auto_mode
    )
    
    
@app.route('/api/device_set_mode/<device_key>', methods=['POST'])
def device_set_mode(device_key):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    mode = data.get('mode', '').lower()

    if mode not in ['auto', 'manual']:
        return jsonify({'error': 'Invalid mode'}), 400

    # This API endpoint should send an MQTT command to the device to change its mode
    # Assuming register 91 controls auto/manual mode (1 for auto, 0 for manual)
    mode_value = 1 if mode == 'auto' else 0
    mqtt_payload = json.dumps({"write": {91: mode_value}})
    mqtt_client.publish(f"{device_key}/request", mqtt_payload)
    
    # Optionally, update the device_states immediately for faster UI feedback
    if device_key in device_states:
        device_states[device_key][91] = mode_value

    return jsonify({'message': f'Mode change command sent to device {device_key} for mode {mode}'})

    
@app.route('/api/device/<device_key>/control', methods=['POST'])
def control_device(device_key):
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json

    with sqlite3.connect(DEVICES_DB_PATH) as conn:
        cursor = conn.execute("SELECT device_key FROM devices WHERE device_key = ?", (device_key,))
        if not cursor.fetchone():
            return jsonify({"error": "Device not found"}), 404

    command = {
        "relay": data.get("relay"),
        "state": data.get("state"),
        "current_limit": data.get("current_limit"),
        "emergency_stop": data.get("emergency_stop")
    }
    mqtt_client.publish(f"{device_key}/request", json.dumps(command))
    return jsonify({"status": "Command sent"})


@app.route('/view-users', methods=['GET', 'POST'])
def view_users():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(USERS_DB_PATH)
    c = conn.cursor()

    if request.method == 'POST':
        new_user = request.form['username']
        new_pass = generate_password_hash(request.form['password'])
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_user, new_pass))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Optionally: flash message

    c.execute("SELECT id, username FROM users")
    users = c.fetchall()
    conn.close()

    return render_template('view_users.html', users=users)


@app.route('/delete-user/<int:user_id>')
def delete_user(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(USERS_DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('view_users'))


@app.route('/admin-logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))
    
# if __name__ == '__main__':
    # socketio.run(app, debug=True) # Use socketio.run for Flask-SocketIO


# if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
