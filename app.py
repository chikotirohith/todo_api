import sqlite3
import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, redirect
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature




# Debugging: Print database path
print("Database absolute path:", os.path.abspath("tasks.db"))
from flask_cors import CORS
# Initialize Flask App
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret-key"  # Change in production
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)  # Short-lived access token
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)  # Long-lived refresh token
app.config["DEBUG"] = True
CORS(app, resources={r"/*": {"origins": "https://todo-frontend-asz1.onrender.com"}}, supports_credentials=True)
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "https://todo-frontend-asz1.onrender.com"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true" 
    return response

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route("/tasks/<int:task_id>", methods=["PUT", "OPTIONS"])
@jwt_required()
def update_task(task_id):
    if request.method == "OPTIONS":  # ✅ Handle CORS preflight request
        response = jsonify({"message": "CORS preflight successful"})
        response.headers.add("Access-Control-Allow-Origin", "https://todo-frontend-asz1.onrender.com")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        return response, 200

    user_id = get_jwt_identity()  # ✅ Get logged-in user ID
    data = request.get_json()

    if not data or "done" not in data:
        return jsonify({"error": "Missing 'done' field"}), 400

    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE tasks SET done = ? WHERE id = ? AND user_id = ?", (data["done"], task_id, user_id))
    conn.commit()
    conn.close()

    response = jsonify({"message": "Task updated successfully"})
    response.headers.add("Access-Control-Allow-Origin", "https://todo-frontend-asz1.onrender.com")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    return response, 200



# ✅ Route to refresh the access token
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)  # This requires a valid refresh token
def refresh():
    user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=user_id)  # Create new access token
    return jsonify(access_token=new_access_token), 200

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "rohithchikoti36@gmail.com"  # Replace with your email
app.config['MAIL_PASSWORD'] = "ozrxdfekiededxib"  # Use your App Password!

mail = Mail(app)

# Serializer for reset tokens
serializer = URLSafeTimedSerializer(app.config["JWT_SECRET_KEY"])


# ✅ Initialize Database
def init_db():
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Tasks Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task TEXT NOT NULL,
            done BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()


init_db()  # Initialize DB


# ✅ Register User
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()  # ✅ Ensure JSON parsing works
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Missing username or password"}), 400

        username = data['username']
        password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()

        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()

        return jsonify({"message": "User registered successfully"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # ✅ Return error for debugging



# ✅ Login & Generate Access + Refresh Tokens
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

   
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user[1], password):
        access_token = create_access_token(identity=str(user[0]))
        refresh_token = create_refresh_token(identity=str(user[0]))
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 200
    return jsonify({"error": "Invalid credentials"}), 401


# ✅ Refresh Token Endpoint
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)  # Requires Refresh Token
def refresh_token():
    user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=user_id)
    response = jsonify({"access_token": new_access_token})
    response.headers.add("Access-Control-Allow-Origin", "https://todo-frontend-asz1.onrender.com")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")

    return response

# ✅ Forgot Password - Send Reset Link
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('username')

    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Generate Token
    token = serializer.dumps(email, salt='password-reset')
    reset_link = f"https://todo-frontend-asz1.onrender.com/reset-password/{token}"

    # Send Email
    try:
        msg = Message("Password Reset Request", sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Click the link to reset your password: {reset_link}"
        mail.send(msg)
        return jsonify({"message": "Reset link sent to email"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ✅ Reset Password API
@app.route('/reset-password/<token>', methods=['GET','POST', 'OPTIONS'])
def reset_password(token):
    if request.method == "OPTIONS":
        response = jsonify({"message": "CORS preflight successful"})
        response.headers.add("Access-Control-Allow-Origin", "https://todo-frontend-asz1.onrender.com")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response, 200
    if request.method == "GET":
        return jsonify({"reset_url": f"https://todo-frontend-asz1.onrender.com/reset-password/{token}"})
    if request.method == "POST":
        try:
            email = serializer.loads(token, salt='password-reset', max_age=600)  # 10-minute expiry
        except SignatureExpired:
            return jsonify({"error": "Token expired"}), 400
        except BadSignature:
            return jsonify({"error": "Invalid token"}), 400

        # ✅ Ensure the request has JSON data
        if not request.is_json:
            return jsonify({"error": "Unsupported Media Type. Use JSON format"}), 415

        data = request.get_json()  # ✅ Get JSON data from request
        if "password" not in data:
            return jsonify({"error": "Missing new password"}), 400

        new_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE username=?", (new_password, email))
        conn.commit()
        conn.close()

        return jsonify({"message": "Password updated successfully"}), 200





# ✅ Get User Tasks
@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    user_id = int(get_jwt_identity())

    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, task, done FROM tasks WHERE user_id = ?', (user_id,))
    tasks = [{"id": row[0], "task": row[1], "done": bool(row[2])} for row in cursor.fetchall()]
    conn.close()
        # ✅ Add CORS headers manually
    response = jsonify(tasks)
    response.headers.add("Access-Control-Allow-Origin", "https://todo-frontend-asz1.onrender.com")  # Allow frontend access
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    
    return response, 200



# ✅ Add Task
@app.route('/tasks', methods=['GET', 'POST', 'OPTIONS'])
@jwt_required(optional=True)  # Allows unauthenticated OPTIONS requests
def add_task():
    if request.method == "OPTIONS":
        response = jsonify({"message": "CORS preflight request successful"})
        response.headers.add("Access-Control-Allow-Origin", "https://todo-frontend-asz1.onrender.com")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        return response, 200
    user_id = int(get_jwt_identity())
    data = request.get_json()

    if not data or "task" not in data:
        return jsonify({"error": "Missing 'task' field"}), 400

    new_task = data["task"].strip()
    if not new_task:
        return jsonify({"error": "Task must be a non-empty string"}), 400

    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO tasks (user_id, task, done) VALUES (?, ?, ?)', (user_id, new_task, False))
    conn.commit()
    task_id = cursor.lastrowid
    conn.close()
        # ✅ Add CORS headers manually
    response = jsonify({"id": task_id, "task": new_task, "done": False})
    response.headers.add("Access-Control-Allow-Origin", "https://todo-frontend-asz1.onrender.com")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    return response



@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    user_id = get_jwt_identity()

    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()

    # ✅ Ensure task belongs to the logged-in user
    cursor.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id))
    conn.commit()
    conn.close()

    return jsonify({"message": "Task deleted successfully"}), 200
@app.route('/tasks/clear', methods=['DELETE'])
@jwt_required()
def clear_all_tasks():
    user_id = get_jwt_identity()

    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tasks WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "All tasks cleared successfully"}), 200



# ✅ Run Flask app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
