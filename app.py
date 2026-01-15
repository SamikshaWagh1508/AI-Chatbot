from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv
from google import genai
from pathlib import Path
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import functools


env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-this")


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatbot.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


api_key = os.getenv("GOOGLE_API_KEY")

client = genai.Client(api_key=api_key)

current_conversation = []



class User(db.Model):
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    conversations = db.relationship('Conversation', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'


class Conversation(db.Model):
    """Conversation model to store chat sessions"""
    __tablename__ = 'conversations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), default='Untitled')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Conversation {self.title}>'


class Message(db.Model):
    """Message model to store individual messages"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    user_message = db.Column(db.Text, nullable=False)
    bot_response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Message {self.id}>'



def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"success": False, "error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """Get current logged-in user"""
    if 'user_id' not in session:
        return None
    return User.query.get(session['user_id'])


def get_current_date_info():
    """Get current date and time"""
    now = datetime.now()
    return f"Current date and time: {now.strftime('%A, %B %d, %Y at %I:%M %p')}"



@app.route("/")
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register new user"""
    if request.method == "POST":
        try:
            data = request.get_json()
            username = data.get("username", "").strip()
            email = data.get("email", "").strip()
            password = data.get("password", "").strip()
            confirm_password = data.get("confirm_password", "").strip()
            
            # Validation
            if not username or not email or not password:
                return jsonify({"success": False, "error": "All fields required"}), 400
            
            if len(username) < 3:
                return jsonify({"success": False, "error": "Username must be at least 3 characters"}), 400
            
            if len(password) < 6:
                return jsonify({"success": False, "error": "Password must be at least 6 characters"}), 400
            
            if password != confirm_password:
                return jsonify({"success": False, "error": "Passwords do not match"}), 400
            
            # Check if user exists
            if User.query.filter_by(username=username).first():
                return jsonify({"success": False, "error": "Username already exists"}), 400
            
            if User.query.filter_by(email=email).first():
                return jsonify({"success": False, "error": "Email already exists"}), 400
            
            # Create new user
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password=hashed_password)
            
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({"success": True, "message": "Registration successful! Please login."})
        
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "error": str(e)}), 500
    
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login user"""
    if request.method == "POST":
        try:
            data = request.get_json()
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()
            
            if not username or not password:
                return jsonify({"success": False, "error": "Username and password required"}), 400
            
            # Find user
            user = User.query.filter_by(username=username).first()
            
            if not user or not check_password_hash(user.password, password):
                return jsonify({"success": False, "error": "Invalid username or password"}), 401
            
            # Create session
            session['user_id'] = user.id
            session['username'] = user.username
            
            return jsonify({"success": True, "message": "Login successful!"})
        
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """User dashboard"""
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))


@app.route("/chat", methods=["POST"])
@login_required
def chat():
    """Handle chat messages"""
    try:
        data = request.get_json()
        user_message = data.get("message", "").strip()
        
        if not user_message:
            return jsonify({"success": False, "error": "Message cannot be empty"}), 400
        
        # Add to conversation
        current_conversation.append(f"User: {user_message}")
        
        # Build conversation text with date
        date_info = get_current_date_info()
        conversation_text = f"{date_info}\n\n" + "\n".join(current_conversation)
        
        # Get AI response
        response = client.models.generate_content(
            model="models/gemini-3-flash-preview",
            contents=conversation_text
        )
        
        bot_reply = response.text
        current_conversation.append(f"Assistant: {bot_reply}")
        
        return jsonify({
            "success": True,
            "reply": bot_reply
        })
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/clear", methods=["POST"])
@login_required
def clear_chat():
    """Clear chat history"""
    global current_conversation
    current_conversation = []
    return jsonify({"success": True, "message": "Chat cleared"})


@app.route("/save-chat", methods=["POST"])
@login_required
def save_chat():
    """Save conversation to database"""
    try:
        data = request.get_json()
        title = data.get("title", "Untitled").strip()
        
        if not current_conversation:
            return jsonify({"success": False, "error": "No messages to save"}), 400
        
        user = get_current_user()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401
        
        # Create conversation
        conversation = Conversation(user_id=user.id, title=title)
        db.session.add(conversation)
        db.session.flush()  # Get the conversation ID
        
        # Save messages
        for i in range(0, len(current_conversation), 2):
            user_msg = current_conversation[i].replace("User: ", "")
            bot_msg = current_conversation[i+1].replace("Assistant: ", "") if i+1 < len(current_conversation) else ""
            
            message = Message(
                conversation_id=conversation.id,
                user_message=user_msg,
                bot_response=bot_msg
            )
            db.session.add(message)
        
        db.session.commit()
        
        return jsonify({"success": True, "message": "Chat saved successfully!"})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/get-conversations", methods=["GET"])
@login_required
def get_conversations():
    """Get user's saved conversations"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401
        
        conversations = Conversation.query.filter_by(user_id=user.id).order_by(Conversation.created_at.desc()).all()
        
        conversation_list = [{
            "id": c.id,
            "title": c.title,
            "created_at": c.created_at.isoformat()
        } for c in conversations]
        
        return jsonify({
            "success": True,
            "conversations": conversation_list
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/get-conversation/<int:conv_id>", methods=["GET"])
@login_required
def get_conversation(conv_id):
    """Get specific conversation messages"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401
        
        conversation = Conversation.query.filter_by(id=conv_id, user_id=user.id).first()
        
        if not conversation:
            return jsonify({"success": False, "error": "Conversation not found"}), 404
        
        messages = [{
            "id": m.id,
            "user_message": m.user_message,
            "bot_response": m.bot_response,
            "created_at": m.created_at.isoformat()
        } for m in conversation.messages]
        
        return jsonify({
            "success": True,
            "conversation": {
                "id": conversation.id,
                "title": conversation.title,
                "messages": messages
            }
        })
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/delete-conversation/<int:conv_id>", methods=["DELETE"])
@login_required
def delete_conversation(conv_id):
    """Delete a conversation"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 401
        
        conversation = Conversation.query.filter_by(id=conv_id, user_id=user.id).first()
        
        if not conversation:
            return jsonify({"success": False, "error": "Conversation not found"}), 404
        
        db.session.delete(conversation)
        db.session.commit()
        
        return jsonify({"success": True, "message": "Conversation deleted"})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database"""
    with app.app_context():
        db.create_all()
        print("✅ Database initialized successfully!")


if __name__ == "__main__":
    # Initialize database on startup
    init_db()
    
    app.run(debug=True, host="0.0.0.0", port=5000)