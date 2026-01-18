from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, disconnect
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

# --- 1. CONFIGURATION & SECURITY ---
load_dotenv()

app = Flask(__name__)

# Use environment variables for sensitive keys
SECRET_KEY = os.getenv('SECRET_KEY')
MONGO_URI = os.getenv('MONGO_URI')
FRONTEND_ORIGIN = os.getenv('FRONTEND_URL', 'http://localhost:5173')

if not SECRET_KEY or not MONGO_URI:
    # Fallback only for local dev if .env is missing, but warn loudly
    print("⚠️ WARNING: SECRET_KEY or MONGO_URI not set in .env. Using insecure defaults for dev.")
    SECRET_KEY = "dev_secret_key_123" 
    MONGO_URI = "mongodb://localhost:27017/" # Assuming local mongo if URI missing

app.config['SECRET_KEY'] = SECRET_KEY

CORS(app, resources={r"/*": {"origins": FRONTEND_ORIGIN}})
socketio = SocketIO(app, cors_allowed_origins=[FRONTEND_ORIGIN])

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://"
)

# --- 2. DATABASE CONNECTION ---
try:
    client = MongoClient(MONGO_URI)
    db = client['tech_community_db']

    users_collection = db['users']
    members_collection = db['members']
    projects_collection = db['projects']
    images_collection = db['project_images']
    messages_collection = db['messages']
    notif_collection = db['notifications']
    # Removed rooms_collection dependency for 1-on-1 chats to simplify logic

    # Indexes
    users_collection.create_index("email", unique=True)
    users_collection.create_index("unique_id", unique=True)
    members_collection.create_index("linked_user_id", unique=True)
    projects_collection.create_index("owner_id")
    images_collection.create_index("project_id", unique=True)
    messages_collection.create_index("room_id") # Optimize chat retrieval

    print("✅ Secure Connection to MongoDB Established!")
except Exception as e:
    print(f"❌ Database Connection Failed: {e}")

# --- 3. AUTH DECORATOR ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'error': 'Authentication Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
            current_username = data.get('username')
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired! Please login again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid Token!'}), 401

        return f(current_user_id, current_username, *args, **kwargs)

    return decorated

# --- 4. SECURITY HELPERS ---
def password_policy(password):
    # Enforce strong passwords
    return bool(re.match(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password))

def create_notification(recipient_id, sender_name, type, message):
    if recipient_id == sender_name: return 

    notif_data = {
        "recipient_id": recipient_id,
        "sender_name": sender_name,
        "type": type,
        "message": message,
        "read": False,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    notif_collection.insert_one(notif_data.copy())
    socketio.emit('new_notification', notif_data)

# --- 5. AUTH ROUTES ---
failed_login = {}

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_user():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    # Relaxed policy for dev, enable strictly for prod
    # if not password_policy(password):
    #     return jsonify({"error": "Weak password. Use at least 8 characters with uppercase, number & symbol."}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 400

    unique_id = f"TDN-{uuid.uuid4()}"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    users_collection.insert_one({
        "unique_id": unique_id,
        "username": username,
        "email": email,
        "password": hashed_password,
        "credits": 0,
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"message": "Registered successfully"}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing credentials"}), 400

    if failed_login.get(email, 0) >= 10: # Increased threshold for dev
        return jsonify({"error": "Account locked. Try after 30 minutes."}), 403

    user = users_collection.find_one({"email": email})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        failed_login[email] = 0 

        token = jwt.encode({
            'user_id': user['unique_id'],
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            "message": "Login successful!",
            "token": token,
            "username": user['username'],
            "email": user['email'],
            "unique_id": user['unique_id'],
            "credits": user.get('credits', 0)
        }), 200

    failed_login[email] = failed_login.get(email, 0) + 1
    return jsonify({"error": "Invalid email or password"}), 401

# --- 6. PROFILE ROUTES ---
@app.route('/join-community', methods=['POST'])
@token_required
def join_community(current_user_id, current_username):
    data = request.json

    if members_collection.find_one({"linked_user_id": current_user_id}):
        return jsonify({"error": "Profile exists"}), 400

    member_data = {
        "linked_user_id": current_user_id,
        "displayName": data.get('displayName'),
        "email": data.get('email'),
        "college": data.get('college'),
        "location": data.get('location'),
        "knownLanguages": data.get('knownLanguages'),
        "strongFoundation": data.get('strongFoundation'),
        "otherSkills": data.get('otherSkills'),
        "socials": {"github": data.get('github'), "linkedin": data.get('linkedin')},
        "joined_at": datetime.datetime.utcnow()
    }
    members_collection.insert_one(member_data)
    create_notification(current_user_id, "System", "system", "Welcome to TechDev!")
    return jsonify({"message": "Profile created"}), 201

@app.route('/update-profile', methods=['PUT'])
@token_required
def update_profile(current_user_id, current_username):
    data = request.json

    update_data = {
        "$set": {
            "displayName": data.get('displayName'),
            "phone": data.get('phone'),
            "college": data.get('college'),
            "department": data.get('department'),
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

    result = members_collection.update_one({"linked_user_id": current_user_id}, update_data)
    if result.matched_count > 0:
        return jsonify({"message": "Profile updated successfully!"}), 200
    else:
        return jsonify({"error": "Profile not found."}), 404

@app.route('/get-profile/<unique_id>', methods=['GET'])
@token_required
def get_profile(current_user_id, current_username, unique_id):
    profile = members_collection.find_one({"linked_user_id": unique_id})
    if profile:
        profile['_id'] = str(profile['_id'])
        user = users_collection.find_one({"unique_id": unique_id})
        profile['credits'] = user.get('credits', 0) if user else 0
        return jsonify(profile), 200
    return jsonify({"message": "Profile not found"}), 404

@app.route('/get-members', methods=['GET'])
@token_required
def get_members(current_user_id, current_username):
    try:
        members = list(members_collection.find().sort("joined_at", -1))
        users = list(users_collection.find({}, {"unique_id": 1, "credits": 1}))
        credit_map = {u['unique_id']: u.get('credits', 0) for u in users}

        for m in members:
            m['_id'] = str(m['_id'])
            m['credits'] = credit_map.get(m['linked_user_id'], 0)
        return jsonify(members), 200
    except Exception:
        return jsonify([]), 500

# --- 7. PROJECT ROUTES ---
@app.route('/create-project', methods=['POST'])
@token_required
def create_project(current_user_id, current_username):
    data = request.json

    title = data.get('title')
    desc = data.get('description')
    image = data.get('image')

    if not title or not desc:
        return jsonify({"error": "Missing title or description"}), 400

    if len(title) > 100 or len(desc) > 500:
        return jsonify({"error": "Title or description too long"}), 400

    project_id = f"PROJ-{uuid.uuid4()}"

    projects_collection.insert_one({
        "project_id": project_id,
        "owner_id": current_user_id,
        "uploader_name": current_username,
        "title": title,
        "description": desc,
        "type": data.get('type', 'General'),
        "has_image": bool(image),
        "is_solved": False,
        "solved_by": None,
        "pending_solvers": [],
        "likes": [],
        "comments": [],
        "created_at": datetime.datetime.utcnow()
    })

    if image:
        if len(image) > 1_000_000:  # limit image size
            return jsonify({"error": "Image too large"}), 400
        images_collection.insert_one({
            "project_id": project_id,
            "image_data": image,
            "uploaded_at": datetime.datetime.utcnow()
        })

    users_collection.update_one({"unique_id": current_user_id}, {"$inc": {"credits": 5}})
    return jsonify({"message": "Project created!", "project_id": project_id}), 201

@app.route('/like-project', methods=['POST'])
@token_required
def like_project(current_user_id, current_username):
    data = request.json
    pid = data.get('project_id')

    project = projects_collection.find_one({"project_id": pid})
    if not project:
        return jsonify({"error": "Not found"}), 404

    if current_user_id in project.get('likes', []):
        projects_collection.update_one({"project_id": pid}, {"$pull": {"likes": current_user_id}})
        liked = False
    else:
        projects_collection.update_one({"project_id": pid}, {"$push": {"likes": current_user_id}})
        liked = True
        if project['owner_id'] != current_user_id:
            create_notification(project['owner_id'], current_username, "like", "liked your post")

    updated_project = projects_collection.find_one({"project_id": pid})
    socketio.emit('project_interaction_update', {"project_id": pid, "likes": updated_project['likes']})
    return jsonify({"success": True, "liked": liked}), 200

@app.route('/add-comment', methods=['POST'])
@token_required
def add_comment(current_user_id, current_username):
    data = request.json
    pid = data.get('project_id')
    text = data.get('text')

    if not text or len(text) > 300:
        return jsonify({"error": "Comment cannot be empty or too long"}), 400

    comment_obj = {
        "id": str(uuid.uuid4()),
        "user_id": current_user_id,
        "username": current_username,
        "text": text,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

    projects_collection.update_one({"project_id": pid}, {"$push": {"comments": comment_obj}})

    project = projects_collection.find_one({"project_id": pid})
    if project and project['owner_id'] != current_user_id:
        create_notification(project['owner_id'], current_username, 'comment', f"commented: {text[:20]}...")

    updated_comments = project.get('comments', []) + [comment_obj]
    socketio.emit('project_comment_update', {"project_id": pid, "comments": updated_comments})
    return jsonify({"success": True}), 200

# --- 8. SOLVE LOGIC ---
@app.route('/claim-solution', methods=['POST'])
@token_required
def claim_solution(current_user_id, current_username):
    data = request.json
    pid = data.get('project_id')
    owner_id = data.get('owner_id')

    if current_user_id == owner_id:
        return jsonify({"error": "You cannot solve your own post"}), 400

    result = projects_collection.update_one(
        {"project_id": pid, "is_solved": False, "pending_solvers.user_id": {"$ne": current_user_id}},
        {"$push": {"pending_solvers": {"user_id": current_user_id, "username": current_username}}}
    )

    if result.modified_count > 0:
        create_notification(owner_id, current_username, 'system', 'claims to have solved your post.')
        return jsonify({"message": "Solution claimed! Waiting for approval."}), 200
    else:
        return jsonify({"message": "Already claimed or post solved."}), 400

@app.route('/verify-solution', methods=['POST'])
@token_required
def verify_solution(current_user_id, current_username):
    data = request.json
    pid = data.get('project_id')
    solver_id = data.get('solver_id')
    solver_name = data.get('solver_name')
    action = data.get('action')

    project = projects_collection.find_one({"project_id": pid})
    if not project or project['owner_id'] != current_user_id:
        return jsonify({"error": "Unauthorized: Only the owner can verify."}), 403

    if action == 'accept':
        if not solver_name:
            solver_user = users_collection.find_one({"unique_id": solver_id})
            solver_name = solver_user['username'] if solver_user else "Unknown Solver"

        projects_collection.update_one(
            {"project_id": pid},
            {"$set": {"is_solved": True, "solved_by": solver_name, "pending_solvers": []}}
        )
        users_collection.update_one({"unique_id": solver_id}, {"$inc": {"credits": 10}})
        create_notification(solver_id, "System", "like", "Your solution was ACCEPTED! +10 Credits")
        return jsonify({"message": "Solution Accepted!"}), 200

    elif action == 'reject':
        projects_collection.update_one(
            {"project_id": pid},
            {"$pull": {"pending_solvers": {"user_id": solver_id}}}
        )
        create_notification(solver_id, "System", "system", "Your solution claim was rejected.")
        return jsonify({"message": "Claim Rejected."}), 200

    return jsonify({"error": "Invalid action"}), 400

# --- 9. DATA FETCHING ---
@app.route('/get-projects', methods=['GET'])
@token_required
def get_projects(current_user_id, current_username):
    try:
        pipeline = [
            {"$sort": {"created_at": -1}},
            {"$limit": 20},
            {"$lookup": {"from": "project_images", "localField": "project_id", "foreignField": "project_id", "as": "image_info"}},
            {"$unwind": {"path": "$image_info", "preserveNullAndEmptyArrays": True}}
        ]
        projects = list(projects_collection.aggregate(pipeline))
        return jsonify(_clean_projects(projects)), 200
    except Exception:
        return jsonify({"error": "Server Error"}), 500

@app.route('/get-user-projects/<user_id>', methods=['GET'])
@token_required
def get_user_projects(current_user_id, current_username, user_id):
    try:
        pipeline = [
            {"$match": {"owner_id": user_id}},
            {"$sort": {"created_at": -1}},
            {"$lookup": {"from": "project_images", "localField": "project_id", "foreignField": "project_id", "as": "image_info"}},
            {"$unwind": {"path": "$image_info", "preserveNullAndEmptyArrays": True}}
        ]
        projects = list(projects_collection.aggregate(pipeline))
        return jsonify(_clean_projects(projects)), 200
    except Exception:
        return jsonify({"error": "Server Error"}), 500

def _clean_projects(projects_list):
    cleaned = []
    for p in projects_list:
        p['_id'] = str(p['_id'])
        if 'image_info' in p and p['image_info']:
            p['image'] = p['image_info'].get('image_data')
        else:
            p['image'] = None
        p.pop('image_info', None)
        p['likes'] = p.get('likes', [])
        p['comments'] = p.get('comments', [])
        p['pending_solvers'] = p.get('pending_solvers', [])
        cleaned.append(p)
    return cleaned

# --- 10. STATS & DASHBOARD ---
@app.route('/get-stats', methods=['GET'])
@token_required
def get_stats(current_user_id, current_username):
    try:
        total_members = members_collection.count_documents({})
        total_projects = projects_collection.count_documents({})

        top_users = list(users_collection.find({}, {"username": 1, "credits": 1}).sort("credits", -1).limit(5))
        leaderboard = [{"username": u["username"], "credits": u.get("credits", 0)} for u in top_users]

        lang_pipeline = [
            {"$group": {"_id": "$strongFoundation", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]
        lang_data = list(members_collection.aggregate(lang_pipeline))
        languages = [{"name": d["_id"] or "Unknown", "value": d["count"]} for d in lang_data]

        recent_members = list(members_collection.find({}, {"displayName": 1, "strongFoundation": 1, "joined_at": 1}).sort("joined_at", -1).limit(6))
        recents = [{"name": m.get("displayName"), "role": m.get("strongFoundation"), "id": str(m["_id"])} for m in recent_members]

        return jsonify({
            "total_members": total_members,
            "total_projects": total_projects,
            "leaderboard": leaderboard,
            "languages": languages,
            "recents": recents
        }), 200
    except Exception as e:
        print(f"Stats Error: {e}")
        return jsonify({"error": "Stats failed"}), 500

# --- 11. NOTIFICATIONS & CHAT ---
@app.route('/get-notifications/<user_id>', methods=['GET'])
@token_required
def get_notifications(current_user_id, current_username, user_id):
    if current_user_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    try:
        notifs = list(notif_collection.find({"recipient_id": user_id}).sort("timestamp", -1))
        for n in notifs:
            n['_id'] = str(n['_id'])
        return jsonify(notifs), 200
    except Exception:
        return jsonify([]), 500

@app.route('/get-unread-count/<user_id>', methods=['GET'])
@token_required
def get_unread_count(current_user_id, current_username, user_id):
    if current_user_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403
    try:
        count = notif_collection.count_documents({"recipient_id": user_id, "read": False})
        return jsonify({"count": count}), 200
    except Exception:
        return jsonify({"count": 0}), 500

@app.route('/mark-notifications-read', methods=['POST'])
@token_required
def mark_read(current_user_id, current_username):
    uid = request.json.get('user_id')
    if current_user_id != uid:
        return jsonify({"error": "Unauthorized"}), 403
    notif_collection.update_many({"recipient_id": uid, "read": False}, {"$set": {"read": True}})
    return jsonify({"success": True}), 200

@app.route('/get-chat-history/<room_id>', methods=['GET'])
@token_required
def get_chat_history(current_user_id, current_username, room_id):
    # Verify user is actually a participant in the room string
    # Logic: room_id is sorted combination of user IDs: "id1_id2"
    if current_user_id not in room_id: 
        return jsonify({"error": "Unauthorized"}), 403

    try:
        messages = list(messages_collection.find({"room_id": room_id}).sort("timestamp", 1))
        cleaned = []
        for m in messages:
            m['_id'] = str(m['_id'])
            cleaned.append(m)
        return jsonify(cleaned), 200
    except Exception:
        return jsonify({"error": "Error"}), 500

@app.route('/change-password', methods=['POST'])
@token_required
def change_password(current_user_id, current_username):
    data = request.json
    user = users_collection.find_one({"unique_id": current_user_id})
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.checkpw(data.get('current_password').encode('utf-8'), user['password']):
        return jsonify({"error": "Incorrect current password"}), 401

    # Relaxed policy check for dev
    # if not password_policy(data.get('new_password')):
    #     return jsonify({"error": "Weak password."}), 400

    hashed_new = bcrypt.hashpw(data.get('new_password').encode('utf-8'), bcrypt.gensalt())
    users_collection.update_one({"unique_id": current_user_id}, {"$set": {"password": hashed_new}})
    return jsonify({"message": "Password changed successfully"}), 200

# --- 12. SOCKETS ---
@socketio.on('connect')
def on_connect():
    token = request.args.get('token')
    if not token:
        # Allow connection without token for basic polling, but join logic should validate
        # Ideally disconnect() if strict auth is required on connect
        return 

@socketio.on('join')
def on_join(data):
    room = data.get("room")
    # For now, simplistic join without deep token validation in socket 
    # (relying on frontend to send correct room string)
    if room:
        join_room(room)

@socketio.on('send_message')
def handle_message(data):
    # In production, validate token from data or session context
    room = data.get('room')
    content = data.get('content')
    sender_id = data.get('sender_id')
    sender_name = data.get('sender_name')

    if not room or not content or not sender_id:
        return

    msg = {
        "room_id": room,
        "sender_id": sender_id,
        "sender_name": sender_name,
        "content": content,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

    messages_collection.insert_one(msg.copy())
    emit('receive_message', msg, room=room)

    # Simple notification logic - check if it's a 1-on-1 chat
    if "_" in room:
        ids = room.split("_")
        recipient = ids[0] if ids[1] == sender_id else ids[1]
        create_notification(recipient, sender_name, 'chat', "sent a message")

# --- 13. RUN SERVER ---
if __name__ == '__main__':
    socketio.run(app, debug=False, port=5000)