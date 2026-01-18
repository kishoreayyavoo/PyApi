from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from pymongo import MongoClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import bcrypt
import uuid
import jwt
import datetime
import os
import re
from dotenv import load_dotenv

# ================== 1. CONFIGURATION ==================
load_dotenv()

app = Flask(__name__)

# Config Variables
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_key_123")
MONGO_URI = os.getenv("MONGO_URI")
FRONTEND_ORIGIN = os.getenv("FRONTEND_URL", "*") # Use "*" for dev, specific URL for prod

app.config["SECRET_KEY"] = SECRET_KEY

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

# ================== 2. DATABASE ==================
try:
    client = MongoClient(MONGO_URI)
    db = client["tech_community_db"]

    # Collections
    users_collection = db["users"]
    members_collection = db["members"]
    projects_collection = db["projects"]
    images_collection = db["project_images"]
    messages_collection = db["messages"]
    notif_collection = db["notifications"]

    # Indexes (Crucial for performance)
    users_collection.create_index("email", unique=True)
    users_collection.create_index("unique_id", unique=True)
    members_collection.create_index("linked_user_id", unique=True)
    projects_collection.create_index("owner_id")
    projects_collection.create_index("created_at")
    messages_collection.create_index("room_id")
    
    print("✅ Connected to MongoDB")
except Exception as e:
    print(f"❌ Database connection error: {e}")

# ================== 3. HELPERS & DECORATORS ==================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth = request.headers.get("Authorization")
            if auth.startswith("Bearer "):
                token = auth.split(" ")[1]

        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            return f(data["user_id"], data.get("username"), *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    return decorated

def create_notification(uid, sender, ntype, msg):
    if uid == sender: return # Don't notify self
    notif = {
        "recipient_id": uid,
        "sender_name": sender,
        "type": ntype,
        "message": msg,
        "read": False,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    notif_collection.insert_one(notif)
    # Convert ID for JSON serialization before emitting
    notif["_id"] = str(notif["_id"]) 
    socketio.emit("new_notification", notif)

def _clean_projects(projects_list):
    """Helper to format project data for frontend"""
    cleaned = []
    for p in projects_list:
        p['_id'] = str(p['_id'])
        # Extract image data if it exists from the aggregation lookup
        if 'image_info' in p and p['image_info']:
            p['image'] = p['image_info'].get('image_data')
        else:
            p['image'] = None
        # Remove the raw lookup array
        p.pop('image_info', None)
        
        p['likes'] = p.get('likes', [])
        p['comments'] = p.get('comments', [])
        p['pending_solvers'] = p.get('pending_solvers', [])
        cleaned.append(p)
    return cleaned

# ================== 4. AUTH ROUTES ==================

@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    d = request.json
    if users_collection.find_one({"email": d["email"]}):
        return jsonify({"error": "Email exists"}), 400

    users_collection.insert_one({
        "unique_id": f"TDN-{uuid.uuid4()}",
        "username": d["username"],
        "email": d["email"],
        "password": bcrypt.hashpw(d["password"].encode(), bcrypt.gensalt()),
        "credits": 0,
        "created_at": datetime.datetime.utcnow()
    })
    return jsonify({"message": "Registered successfully"}), 201

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    d = request.json
    user = users_collection.find_one({"email": d["email"]})

    if not user or not bcrypt.checkpw(d["password"].encode(), user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode({
        "user_id": user["unique_id"],
        "username": user["username"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24) # 24h token
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({
        "token": token,
        "username": user["username"],
        "unique_id": user["unique_id"],
        "credits": user.get("credits", 0)
    })

# ================== 5. PROFILE ROUTES ==================

@app.route("/join-community", methods=["POST"])
@token_required
def join_community(uid, uname):
    d = request.json
    if members_collection.find_one({"linked_user_id": uid}):
        return jsonify({"error": "Profile already exists"}), 400

    members_collection.insert_one({
        "linked_user_id": uid,
        "displayName": d.get("displayName"),
        "email": d.get("email"),
        "college": d.get("college"),
        "location": d.get("location"),
        "knownLanguages": d.get('knownLanguages', ""),
        "strongFoundation": d.get('strongFoundation', ""),
        "otherSkills": d.get('otherSkills', ""),
        "socials": {"github": d.get('github'), "linkedin": d.get('linkedin')},
        "joined_at": datetime.datetime.utcnow()
    })
    create_notification(uid, "System", "system", "Welcome to TechDev Nexus!")
    return jsonify({"message": "Profile created"}), 201

@app.route('/update-profile', methods=['PUT'])
@token_required
def update_profile(uid, uname):
    data = request.json
    update_data = {
        "$set": {
            "displayName": data.get('displayName'),
            "college": data.get('college'),
            "location": data.get('location'),
            "knownLanguages": data.get('knownLanguages'),
            "strongFoundation": data.get('strongFoundation'),
            "otherSkills": data.get('otherSkills'),
            "socials": {
                "github": data.get('github'),
                "linkedin": data.get('linkedin')
            },
            "updated_at": datetime.datetime.utcnow()
        }
    }
    members_collection.update_one({"linked_user_id": uid}, update_data)
    return jsonify({"message": "Profile updated"}), 200

@app.route('/get-profile/<unique_id>', methods=['GET'])
@token_required
def get_profile(uid, uname, unique_id):
    profile = members_collection.find_one({"linked_user_id": unique_id})
    if profile:
        profile['_id'] = str(profile['_id'])
        user = users_collection.find_one({"unique_id": unique_id})
        profile['credits'] = user.get('credits', 0) if user else 0
        return jsonify(profile), 200
    return jsonify({"message": "Profile not found"}), 404

@app.route('/get-members', methods=['GET'])
@token_required
def get_members(uid, uname):
    members = list(members_collection.find().sort("joined_at", -1))
    # Fetch credits to display on member cards
    users = list(users_collection.find({}, {"unique_id": 1, "credits": 1}))
    credit_map = {u['unique_id']: u.get('credits', 0) for u in users}

    for m in members:
        m['_id'] = str(m['_id'])
        m['credits'] = credit_map.get(m['linked_user_id'], 0)
    return jsonify(members), 200

# ================== 6. PROJECT ROUTES ==================

@app.route("/create-project", methods=["POST"])
@token_required
def create_project(uid, uname):
    d = request.json
    pid = f"PROJ-{uuid.uuid4()}"
    image = d.get('image')

    projects_collection.insert_one({
        "project_id": pid,
        "owner_id": uid,
        "uploader_name": uname,
        "title": d["title"],
        "description": d["description"],
        "type": d.get('type', 'General'),
        "has_image": bool(image),
        "is_solved": False,
        "solved_by": None,
        "pending_solvers": [],
        "likes": [],
        "comments": [],
        "created_at": datetime.datetime.utcnow()
    })

    if image:
        images_collection.insert_one({
            "project_id": pid,
            "image_data": image
        })

    # Reward for posting
    users_collection.update_one({"unique_id": uid}, {"$inc": {"credits": 5}})
    return jsonify({"project_id": pid}), 201

@app.route("/get-projects", methods=["GET"])
@token_required
def get_projects(uid, uname):
    # Aggregation pipeline to join projects with their images efficiently
    pipeline = [
        {"$sort": {"created_at": -1}},
        {"$limit": 50},
        {"$lookup": {
            "from": "project_images", 
            "localField": "project_id", 
            "foreignField": "project_id", 
            "as": "image_info"
        }},
        {"$unwind": {"path": "$image_info", "preserveNullAndEmptyArrays": True}}
    ]
    projects = list(projects_collection.aggregate(pipeline))
    return jsonify(_clean_projects(projects))

@app.route('/like-project', methods=['POST'])
@token_required
def like_project(uid, uname):
    data = request.json
    pid = data.get('project_id')
    project = projects_collection.find_one({"project_id": pid})
    
    if not project: return jsonify({"error": "Not found"}), 404

    if uid in project.get('likes', []):
        projects_collection.update_one({"project_id": pid}, {"$pull": {"likes": uid}})
        liked = False
    else:
        projects_collection.update_one({"project_id": pid}, {"$push": {"likes": uid}})
        liked = True
        create_notification(project['owner_id'], uname, "like", "liked your post")

    return jsonify({"success": True, "liked": liked}), 200

@app.route('/add-comment', methods=['POST'])
@token_required
def add_comment(uid, uname):
    data = request.json
    pid = data.get('project_id')
    text = data.get('text')

    comment_obj = {
        "id": str(uuid.uuid4()),
        "user_id": uid,
        "username": uname,
        "text": text,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    projects_collection.update_one({"project_id": pid}, {"$push": {"comments": comment_obj}})
    
    # Notify owner
    project = projects_collection.find_one({"project_id": pid})
    create_notification(project['owner_id'], uname, 'comment', f"commented: {text[:20]}...")
    
    return jsonify({"success": True}), 200

# ================== 7. GAMIFICATION & SOLVING ==================

@app.route('/claim-solution', methods=['POST'])
@token_required
def claim_solution(uid, uname):
    data = request.json
    pid = data.get('project_id')
    owner_id = data.get('owner_id')

    if uid == owner_id:
        return jsonify({"error": "Cannot solve own post"}), 400

    projects_collection.update_one(
        {"project_id": pid},
        {"$push": {"pending_solvers": {"user_id": uid, "username": uname}}}
    )
    create_notification(owner_id, uname, 'system', 'claims to have solved your issue.')
    return jsonify({"message": "Solution claimed"}), 200

@app.route('/verify-solution', methods=['POST'])
@token_required
def verify_solution(uid, uname):
    data = request.json
    pid = data.get('project_id')
    solver_id = data.get('solver_id')
    action = data.get('action')

    # Security check: only owner can verify
    project = projects_collection.find_one({"project_id": pid})
    if project['owner_id'] != uid:
        return jsonify({"error": "Unauthorized"}), 403

    if action == 'accept':
        solver_name = data.get('solver_name', "Unknown")
        projects_collection.update_one(
            {"project_id": pid},
            {"$set": {"is_solved": True, "solved_by": solver_name, "pending_solvers": []}}
        )
        # Give credits to solver
        users_collection.update_one({"unique_id": solver_id}, {"$inc": {"credits": 10}})
        create_notification(solver_id, "System", "like", "Solution ACCEPTED! +10 Credits")
        return jsonify({"message": "Accepted"}), 200

    elif action == 'reject':
        projects_collection.update_one(
            {"project_id": pid},
            {"$pull": {"pending_solvers": {"user_id": solver_id}}}
        )
        create_notification(solver_id, "System", "system", "Solution claim rejected.")
        return jsonify({"message": "Rejected"}), 200

    return jsonify({"error": "Invalid action"}), 400

# ================== 8. STATS DASHBOARD ==================

@app.route('/get-stats', methods=['GET'])
@token_required
def get_stats(uid, uname):
    total_members = members_collection.count_documents({})
    total_projects = projects_collection.count_documents({})
    
    # Leaderboard
    top_users = list(users_collection.find({}, {"username": 1, "credits": 1}).sort("credits", -1).limit(5))
    leaderboard = [{"username": u["username"], "credits": u.get("credits", 0)} for u in top_users]

    # Languages Distribution
    lang_pipeline = [
        {"$group": {"_id": "$strongFoundation", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    lang_data = list(members_collection.aggregate(lang_pipeline))
    languages = [{"name": d["_id"] or "Unknown", "value": d["count"]} for d in lang_data]

    # Recent Joins
    recent_members = list(members_collection.find().sort("joined_at", -1).limit(6))
    recents = [{"name": m.get("displayName"), "role": m.get("strongFoundation"), "id": str(m["_id"])} for m in recent_members]

    return jsonify({
        "total_members": total_members,
        "total_projects": total_projects,
        "leaderboard": leaderboard,
        "languages": languages,
        "recents": recents
    })

# ================== 9. NOTIFICATIONS & CHAT ==================

@app.route('/get-notifications/<user_id>', methods=['GET'])
@token_required
def get_notifications(uid, uname, user_id):
    if uid != user_id: return jsonify({"error": "Unauthorized"}), 403
    
    notifs = list(notif_collection.find({"recipient_id": user_id}).sort("timestamp", -1))
    for n in notifs: n['_id'] = str(n['_id'])
    return jsonify(notifs), 200

@app.route('/mark-notifications-read', methods=['POST'])
@token_required
def mark_read(uid, uname):
    target_id = request.json.get('user_id')
    if uid != target_id: return jsonify({"error": "Unauthorized"}), 403
    
    notif_collection.update_many({"recipient_id": target_id, "read": False}, {"$set": {"read": True}})
    return jsonify({"success": True}), 200

@app.route("/get-chat-history/<room>", methods=["GET"])
@token_required
def chat_history(uid, uname, room):
    # Security: Ensure requesting user is part of the room string (e.g., "id1_id2")
    if uid not in room: return jsonify({"error": "Unauthorized"}), 403
    
    msgs = list(messages_collection.find({"room_id": room}).sort("timestamp", 1))
    for m in msgs: m["_id"] = str(m["_id"])
    return jsonify(msgs)

# ================== 10. REAL-TIME SOCKETS ==================

@socketio.on("join")
def on_join(data):
    join_room(data["room"])

@socketio.on("send_message")
def handle_message(data):
    msg = {
        "room_id": data["room"],
        "sender_id": data["sender_id"],
        "sender_name": data["sender_name"],
        "content": data["content"],
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    messages_collection.insert_one(msg.copy())
    
    # Send to Room
    emit("receive_message", msg, room=data["room"])
    
    # Notify Recipient if it's a DM
    room_id = data["room"]
    if "_" in room_id:
        ids = room_id.split("_")
        recipient = ids[0] if ids[1] == data["sender_id"] else ids[1]
        create_notification(recipient, data["sender_name"], 'chat', "sent a message")

# ================== 11. HEALTH & RUN ==================

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "API running"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False 
    )
