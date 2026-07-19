from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime

app = Flask(__name__)

app.config["SECRET_KEY"] = "mysecretkey123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


with app.app_context():
    db.create_all()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"message": "Token missing"}), 401

        try:
            token = token.split(" ")[1]
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except Exception:
            return jsonify({"message": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated


@app.route("/")
def home():
    return jsonify({"message": "Flask JWT CRUD API Running"})


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"message": "User already exists"}), 400

    user = User(
        username=data["username"],
        password=generate_password_hash(data["password"])
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Registered Successfully"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    user = User.query.filter_by(username=data["username"]).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    if not check_password_hash(user.password, data["password"]):
        return jsonify({"message": "Wrong password"}), 401

    token = jwt.encode(
        {
            "username": user.username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    return jsonify({"token": token})


@app.route("/profile")
@token_required
def profile():
    return jsonify({"message": "Welcome! Login Successful"})


@app.route("/users")
@token_required
def users():
    users = User.query.all()

    return jsonify([
        {
            "id": u.id,
            "username": u.username
        }
        for u in users
    ])


@app.route("/users/<int:user_id>")
@token_required
def single_user(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username
    })


@app.route("/users/<int:user_id>", methods=["PUT"])
@token_required
def update_user(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()

    if "username" in data:
        user.username = data["username"]

    if "password" in data:
        user.password = generate_password_hash(data["password"])

    db.session.commit()

    return jsonify({"message": "User updated successfully"})


@app.route("/users/<int:user_id>", methods=["DELETE"])
@token_required
def delete_user(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User deleted successfully"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
