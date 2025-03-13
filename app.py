import sqlite3
from flask import Flask, jsonify, request

app = Flask(__name__)

# Initialize Database
def init_db():
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            done BOOLEAN NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()  # Initialize database

# Get all tasks
# add22222222

@app.route('/tasks', methods=['GET'])
def get_tasks():
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tasks')
    tasks = [{"id": row[0], "task": row[1], "done": bool(row[2])} for row in cursor.fetchall()]
    conn.close()
    return jsonify(tasks)

# Get a single task by ID
@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tasks WHERE id = ?', (task_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return jsonify({"id": row[0], "task": row[1], "done": bool(row[2])})
    return jsonify({"error": "Task not found"}), 404

# Add a new task
@app.route('/tasks', methods=['POST'])
def add_task():
    new_task = request.json["task"]
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO tasks (task, done) VALUES (?, ?)', (new_task, False))
    conn.commit()
    task_id = cursor.lastrowid
    conn.close()
    return jsonify({"id": task_id, "task": new_task, "done": False}), 201

# Update a task by ID
@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    data = request.json
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE tasks SET task = ?, done = ? WHERE id = ?', (data["task"], data["done"], task_id))
    conn.commit()
    conn.close()
    return jsonify({"id": task_id, "task": data["task"], "done": data["done"]})

# Delete a task by ID
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Task deleted successfully"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

