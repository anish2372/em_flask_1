from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import paho.mqtt.client as mqtt
from threading import Thread

# Get absolute path to devices.db
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# DEVICES_DB_PATH = os.path.join(BASE_DIR, "devices.db")
DEVICES_DB_PATH = os.path.join(os.path.dirname(__file__), 'devices.db')
print("USING DEVICES DB:", DEVICES_DB_PATH)
conn = sqlite3.connect(DEVICES_DB_PATH)
c = conn.cursor()
USERS_DB_PATH = os.path.join(BASE_DIR, "users.db")


app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change this for production



MQTT_BROKER = "mqtt.eclipseprojects.io"
MQTT_PORT = 1883
MQTT_TOPIC_REQUEST = "{mac}/request"
MQTT_TOPIC_RESPONSE = "{mac}/response"

mqtt_client = mqtt.Client(protocol=mqtt.MQTTv311)

device_states = {}

def on_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Connected to MQTT Broker.")
        # client.subscribe("+/response")
        conn = sqlite3.connect(DEVICES_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT device_key FROM devices")
        device_keys = [row[0] for row in c.fetchall()]
        conn.close()

        for key in device_keys:
            topic = f"{key}/response"
            client.subscribe(topic)
    else:
        print(f"❌ Failed to connect, reason code: {rc}")

def on_mqtt_message(client, userdata, msg):
    print(f"📩 Message received on {msg.topic}: {msg.payload.decode()}")

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
    
    # Also pass devices to sidebar
    conn = sqlite3.connect(DEVICES_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT device_key, COALESCE(name, '') as name FROM devices")
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
    c.execute("SELECT device_key, COALESCE(name, '') as name FROM devices")
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

        if len(device_key) != 16:
            return "Device key must be 16 digits"

        try:
            conn = sqlite3.connect(DEVICES_DB_PATH)
            c = conn.cursor()
            c.execute(
    "INSERT INTO devices (device_key, ssid, wifi_password, device_name) VALUES (?, ?, ?, ?)",
    (device_key, ssid, wifi_password, 'Unnamed Device')

            )
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            return "Device already registered."

    # Pass devices so sidebar shows properly on add_device page
    conn = sqlite3.connect(DEVICES_DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT device_key, COALESCE(device_name, '') as name FROM devices")

    devices = c.fetchall()
    conn.close()

    return render_template('add_device.html', devices=devices)





# Admin login and management routes unchanged except fix db filenames consistency:
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
    c.execute("SELECT device_key, ssid, wifi_password FROM devices")
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
    return redirect(url_for('view_devices'))
    
    
    

    

# @app.route('/device/<device_key>', methods=['GET', 'POST'])
# def device_page(device_key):
    # if 'username' not in session:
        # return redirect(url_for('login'))

    # conn = sqlite3.connect(DEVICES_DB_PATH)
    # conn.row_factory = sqlite3.Row
    # c = conn.cursor()

    # Update name if POST
    # if request.method == 'POST':
        # new_name = request.form.get('device_name', '').strip()
        # c.execute("UPDATE devices SET device_name = ? WHERE device_key = ?", (new_name, device_key))
        # conn.commit()

    # Fetch the updated device
    # c.execute("SELECT * FROM devices WHERE device_key = ?", (device_key,))
    # device = c.fetchone()

    # Fetch all devices for sidebar (updated list)
    # c.execute("SELECT device_key, device_name FROM devices")
    # devices = c.fetchall()

    # conn.close()

    # if not device:
        # return "Device not found", 404

    # return render_template("device_page.html", device=device, devices=devices)
    
    

# @app.route('/api/device/<device_key>', methods=['GET'])
# def get_device_data(device_key):
    # if 'username' not in session:
        # return jsonify({"error": "Unauthorized"}), 401
    # with sqlite3.connect(DEVICES_DB_PATH) as conn:
        # conn.row_factory = sqlite3.Row
        # device = conn.execute("SELECT * FROM devices WHERE device_key = ?", (device_key,)).fetchone()
    # if not device:
        # return jsonify({"error": "Device not found"}), 404

    # state = device_states.get(device_key, {
        # "relays": [0]*8,
        # "fuses": [1]*8,
        # "currents": [0.0]*8,
        # "voltage": 0.0,
        # "frequency": 0.0,
        # "powers": [0.0]*8,
        # "energies": [0.0]*8,
        # "postpaid_energies": [0.0]*8,
        # "voltage_trips": [0]*8,
        # "current_trips": [0]*8,
        # "current_limits": [5.0]*8,
        # "auto_mode": 1,
        # "emergency_stop": 0
    # })

    # return jsonify(state)
    
    
# @app.route('/device/<device_key>', methods=['GET', 'POST'])
# def device_page(device_key):
    # if 'username' not in session:
        # return redirect(url_for('login'))

    # conn = sqlite3.connect(DEVICES_DB_PATH)
    # conn.row_factory = sqlite3.Row
    # c = conn.cursor()

    # Update name if POST
    # if request.method == 'POST':
        # new_name = request.form.get('device_name', '').strip()
        # c.execute("UPDATE devices SET device_name = ? WHERE device_key = ?", (new_name, device_key))
        # conn.commit()

    # Fetch the updated device
    # c.execute("SELECT * FROM devices WHERE device_key = ?", (device_key,))
    # device = c.fetchone()

    # Fetch all devices for sidebar (updated list)
    # c.execute("SELECT device_key, device_name FROM devices")
    # devices = c.fetchall()

    # conn.close()

    # if not device:
        # return "Device not found", 404

    # return render_template("device_page.html", device=device, devices=devices)
    
    
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

    # Fetch the updated device with mode
    c.execute("SELECT * FROM devices WHERE device_key = ?", (device_key,))
    device = c.fetchone()

    # Fetch all devices for sidebar
    c.execute("SELECT device_key, device_name FROM devices")
    devices = c.fetchall()

    conn.close()

    if not device:
        return "Device not found", 404

    # Pass mode flag for template (True if auto)
    is_auto_mode = (device['mode'] == 'auto')

    return render_template("device_page.html", device=device, devices=devices, isAutoMode=is_auto_mode)





    
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
    mqtt_client.publish(MQTT_TOPIC_REQUEST.format(mac=device_key), json.dumps(command))
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
    
    
    




if __name__ == '__main__':
    app.run(debug=True)
