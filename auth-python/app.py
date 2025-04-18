from flask import Flask, request, jsonify, send_from_directory
import json
import os

app = Flask(__name__, static_folder="public")

USERS_FILE = "users.json"

def read_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def write_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

@app.route("/")
def serve_index():
    return send_from_directory("public", "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory("public", path)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    users = read_users()
    for user in users:
        if user["username"] == username and user["password"] == password:
            return jsonify(success=True, message="Вхід успішний!")
    return jsonify(success=False, message="Невірний логін або пароль")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    users = read_users()
    if any(u["username"] == username for u in users):
        return jsonify(success=False, message="Користувач з таким логіном вже існує")
    users.append({"username": username, "password": password})
    write_users(users)
    return jsonify(success=True, message="Реєстрація успішна!")

if __name__ == "__main__":
    app.run(debug=True)
