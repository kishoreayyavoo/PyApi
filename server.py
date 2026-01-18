from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import uuid
import datetime
import os
import firebase_admin
from firebase_admin import credentials, auth, firestore

# ================== 1. CONFIGURATION ==================
app = Flask(__name__)

# Config Variables
FRONTEND_ORIGIN = os.getenv("FRONTEND_URL", "*")  # Use "*" for dev, specific URL for prod

# CORS: Allow credentials for Auth
CORS(app, supports_credentials=True, resources={r"/*": {"origins": FRONTEND_ORIGIN}})

# SocketIO: Async mode threading is safer for basic Render deployments
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://"
)

# ================== 2. FIREBASE ==================

# Initialize Firebase Admin
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)

db = firestore.client()

# Collections
users_collection = db.collection("users")
members_collection = db.collection("members")
projects_collection = db.collection("projects")
images_collection = db.collection("project_images")
messages_collection = db.collection("messages")
notif_collection = db.collection("notifications")


# ================== 3. HELPERS & DECORATORS ==================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers.get("Authorization")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            decoded_token = auth.verify_id_token(token)
            user_id = decoded_token["uid"]
            return f(user_id, *args, **kwargs)
        except Exception as e:
            return jsonify({"error": "Invalid or expired token"}), 401

    return decorated


def create_notification(uid, sender, ntype, msg):
    if uid == sender:
        return  # Don't notify self

    notif = {
        "recipient_id": uid,
        "sender_name": sender,
        "type": ntype,
        "message": msg,
        "read": False,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

    notif_collection.add(notif)
    socketio.emit("new_notification", notif)


def _clean_projects(projects_list):
    cleaned = []
    for p in projects_list:
        p["id"] = p.id
        p_data = p.to_dict()

        p_data["likes"] = p_data.get("likes", [])
        p_data["comments"] = p_data.get("comments", [])
        p_data["pending_solvers"] = p_data.get("pending_solvers", [])
        cleaned.append(p_data)

    return cleaned


# ================== 4. AUTH ROUTES ==================

@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    d = request.json
    email = d["email"]

    user_exists = users_collection.where("email", "==", email).get()
    if user_exists:
        return jsonify({"error": "Email exists"}), 400

    # Create Firebase user
    firebase_user = auth.create_user(
        email=email,
        password=d["password"],
        display_name=d["username"]
    )

    users_collection.add({
        "uid": firebase_user.uid,
        "username": d["username"],
        "email": email,
        "credits": 0,
        "created_at": datetime.datetime.utcnow().isoformat()
    })

    return jsonify({"message": "Registered successfully"}), 201


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    return jsonify({"message": "Login handled by Firebase client SDK"}), 200


# ================== 5. PROFILE ROUTES ==================

@app.route("/join-community", methods=["POST"])
@token_required
def join_community(uid):
    d = request.json
    member_exists = members_collection.where("linked_user_id", "==", uid).get()

    if member_exists:
        return jsonify({"error": "Profile already exists"}), 400

    members_collection.add({
        "linked_user_id": uid,
        "displayName": d.get("displayName"),
        "email": d.get("email"),
        "college": d.get("college"),
        "location": d.get("location"),
        "knownLanguages": d.get("knownLanguages", ""),
        "strongFoundation": d.get("strongFoundation", ""),
        "otherSkills": d.get("otherSkills", ""),
        "socials": {"github": d.get("github"), "linkedin": d.get("linkedin")},
        "joined_at": datetime.datetime.utcnow().isoformat()
    })

    create_notification(uid, "System", "system", "Welcome to TechDev Nexus!")
    return jsonify({"message": "Profile created"}), 201


@app.route("/update-profile", methods=["PUT"])
@token_required
def update_profile(uid):
    data = request.json

    member_doc = members_collection.where("linked_user_id", "==", uid).get()
    if not member_doc:
        return jsonify({"error": "Profile not found"}), 404

    member_id = member_doc[0].id
    members_collection.document(member_id).update({
        "displayName": data.get("displayName"),
        "college": data.get("college"),
        "location": data.get("location"),
        "knownLanguages": data.get("knownLanguages"),
        "strongFoundation": data.get("strongFoundation"),
        "otherSkills": data.get("otherSkills"),
        "socials": {
            "github": data.get("github"),
            "linkedin": data.get("linkedin")
        },
        "updated_at": datetime.datetime.utcnow().isoformat()
    })

    return jsonify({"message": "Profile updated"}), 200


# ================== 6. PROJECT ROUTES ==================

@app.route("/create-project", methods=["POST"])
@token_required
def create_project(uid):
    d = request.json
    pid = f"PROJ-{uuid.uuid4()}"

    projects_collection.add({
        "project_id": pid,
        "owner_id": uid,
        "uploader_name": d.get("uploader_name"),
        "title": d["title"],
        "description": d["description"],
        "type": d.get("type", "General"),
        "has_image": bool(d.get("image")),
        "is_solved": False,
        "solved_by": None,
        "pending_solvers": [],
        "likes": [],
        "comments": [],
        "created_at": datetime.datetime.utcnow().isoformat()
    })

    if d.get("image"):
        images_collection.add({
            "project_id": pid,
            "image_data": d.get("image")
        })

    return jsonify({"project_id": pid}), 201


@app.route("/get-projects", methods=["GET"])
@token_required
def get_projects(uid):
    projects = projects_collection.order_by("created_at", direction=firestore.Query.DESCENDING).limit(50).get()
    return jsonify(_clean_projects(projects))


# ================== 7. CHAT + NOTIFICATIONS ==================

@app.route("/get-chat-history/<room>", methods=["GET"])
@token_required
def chat_history(uid, room):
    if uid not in room:
        return jsonify({"error": "Unauthorized"}), 403

    msgs = messages_collection.where("room_id", "==", room).order_by("timestamp").get()
    messages = [m.to_dict() for m in msgs]
    return jsonify(messages)


@socketio.on("send_message")
def handle_message(data):
    msg = {
        "room_id": data["room"],
        "sender_id": data["sender_id"],
        "sender_name": data["sender_name"],
        "content": data["content"],
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

    messages_collection.add(msg)
    emit("receive_message", msg, room=data["room"])

    room_id = data["room"]
    if "_" in room_id:
        ids = room_id.split("_")
        recipient = ids[0] if ids[1] == data["sender_id"] else ids[1]
        create_notification(recipient, data["sender_name"], "chat", "sent a message")


# ================== 8. HEALTH & RUN ==================

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "API running"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
