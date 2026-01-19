import os
import json
import time
import requests
import pymysql.cursors
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Configuration & Initialization ---
app = Flask(__name__)
# Load mandatory configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['GEMINI_API_KEY'] = os.getenv('GEMINI_API_KEY')
app.config['MODEL_NAME'] = os.getenv('MODEL_NAME')
app.config['AI_SERVER_URL'] = os.getenv('AI_SERVER_URL')

# MySQL DB Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'db': os.getenv('DB_NAME'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# Enable CORS for local development (and ngrok)
CORS(app)

# --- Database & Auth Helpers ---

def get_db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        connection = pymysql.connect(**DB_CONFIG)
        return connection
    except Exception as e:
        print(f"Database connection error: {e}. Check .env file and ensure MySQL is running.")
        return None

def hash_password(password):
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed_password):
    """Checks a plain password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_jwt_token(user_id):
    """Creates a JWT token valid for 24 hours."""
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24),
        'iat': datetime.now(timezone.utc)
    }
    secret = app.config.get('SECRET_KEY')
    if not secret:
        raise Exception("JWT_SECRET_KEY is not set. Check your .env file.")
    return jwt.encode(payload, secret, algorithm='HS256')

def decode_jwt_token(token):
    """Decodes a JWT token, handling expiration and signature errors."""
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired.'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token.'}

def auth_required(f):
    """Decorator to require a valid JWT token in the Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Authorization token is missing or invalid.'}), 401
        
        token = auth_header.split(' ')[1]
        payload = decode_jwt_token(token)

        if 'error' in payload:
            return jsonify({'message': payload['error']}), 401
        
        return f(payload['user_id'], *args, **kwargs)

    return decorated

def log_message_to_db(user_id: int, role: str, content: str):
    """Logs a message (user or AI) to the messages table."""
    connection = get_db_connection()
    if not connection:
        print("Skipping DB logging due to connection failure.")
        return

    try:
        with connection.cursor() as cursor:
            sql = "INSERT INTO messages (user_id, role, content) VALUES (%s, %s, %s)"
            cursor.execute(sql, (user_id, role, content))
        connection.commit()
    except Exception as e:
        print(f"Error logging message to database: {e}")
    finally:
        if connection: connection.close()

def make_api_call_with_backoff(payload, api_url, max_retries=5):
    """Handles Gemini API call with exponential backoff."""
    for attempt in range(max_retries):
        try:
            response = requests.post(
                api_url, 
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload)
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code in [429, 500, 503] and attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"Rate limit or server error ({response.status_code}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise e
        except requests.exceptions.RequestException as e:
            print(f"Network request error on attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise e
    return {}

# --- API Routes: Authentication ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required.'}), 400
    
    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400

    connection = get_db_connection()
    if not connection:
        return jsonify({'message': 'Database connection failed.'}), 500

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({'message': 'User with this email already exists.'}), 409

            hashed_pw = hash_password(password)
            sql = "INSERT INTO users (email, password_hash) VALUES (%s, %s)"
            cursor.execute(sql, (email, hashed_pw))
            connection.commit()
            
            user_id = cursor.lastrowid
            token = create_jwt_token(user_id)
            
            return jsonify({
                'message': 'Registration successful.', 
                'token': token, 
                'user_id': user_id
            }), 201

    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'message': 'An internal error occurred during registration.'}), 500
    finally:
        if connection: connection.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required.'}), 400

    connection = get_db_connection()
    if not connection:
        return jsonify({'message': 'Database connection failed.'}), 500

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT user_id, password_hash FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user or not check_password(password, user['password_hash']):
                return jsonify({'message': 'Invalid email or password.'}), 401
            
            token = create_jwt_token(user['user_id'])
            return jsonify({
                'message': 'Login successful.', 
                'token': token, 
                'user_id': user['user_id']
            }), 200

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'message': 'An internal error occurred during login.'}), 500
    finally:
        if connection: connection.close()

# --- API Route: Gemini Generation (Protected) ---

@app.route('/api/generate', methods=['POST'])
@auth_required
def generate_content(user_id):
    """Handles the user request, logs the prompt, calls Gemini, and logs the response."""
    data = request.get_json()
    prompt = data.get('prompt')
    
    if not prompt:
        return jsonify({'message': 'Missing prompt parameter.'}), 400

    gemini_api_key = app.config.get('GEMINI_API_KEY')
    model_name = app.config.get('MODEL_NAME')
    
    if not gemini_api_key or not model_name:
        return jsonify({'message': 'Server Configuration Error: GEMINI_API_KEY or MODEL_NAME is missing. Check your .env file.'}), 500

    try:
        # 1. Log the user's message
        log_message_to_db(user_id, 'user', prompt)
        
        # 2. Construct API Payload for Gemini
        # --- API URL is correctly constructed inside the function ---
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={gemini_api_key}"
        payload = {
            'contents': [{'parts': [{'text': prompt}]}],
            'tools': [{'google_search': {}}], # Enable search grounding
            'systemInstruction': {
                'parts': [{'text': 'You are Chamsi, a friendly and helpful AI assistant. Provide concise and accurate answers regarding health as a whole.'}],
            },
        }

        # 3. Call the Gemini API
        result = make_api_call_with_backoff(payload, api_url)
        
        candidate = result.get('candidates', [{}])[0]
        generated_text = candidate.get('content', {}).get('parts', [{}])[0].get('text', 'No response text found.')

        # 4. Log the AI's response
        log_message_to_db(user_id, 'ai', generated_text)

        # 5. Extract grounding sources (citations)
        sources = []
        grounding_metadata = candidate.get('groundingMetadata')
        if grounding_metadata and grounding_metadata.get('groundingAttributions'):
            sources = [
                {
                    'uri': attribution.get('web', {}).get('uri'),
                    'title': attribution.get('web', {}).get('title'),
                }
                for attribution in grounding_metadata['groundingAttributions']
                if attribution.get('web', {}).get('uri') and attribution.get('web', {}).get('title')
            ]
        
        return jsonify({ 
            'response': generated_text,
            'sources': sources,
            'user_id': user_id
        }), 200

    except Exception as e:
        print(f"Gemini API Error: {e}")
        log_message_to_db(user_id, 'ai', f'Error: {e}')
        return jsonify({'message': f'AI processing error: {e}.'}), 500

# --- Frontend Serving Route (Single File) ---

@app.route('/', methods=['GET'])
def index():
    """Serves the single-page HTML frontend with TailwindCSS, embedded in the Flask app."""
    return render_template_string(HTML_TEMPLATE, ai_server_url=app.config['AI_SERVER_URL'])


# --- EMBEDDED HTML/CSS/JS FRONTEND ---

# This HTML includes the Auth Forms (Login/Register) and the main Chat Interface.
# It uses JavaScript to handle client-side routing, JWT storage, and communication with the Flask backend.

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chamsi AI - Secure Chat</title>
<!-- Load Tailwind CSS -->
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                    },
                    colors: {
                        'chamsi-green': '#4ba276',
                        'chamsi-red': '#ea667c',
                        'primary-bg': '#f8fafc', // slate-50
                        'secondary-bg': '#ffffff',
                    }
                }
            }
        }
    </script>

    <style>
       
        /* Custom scrollbar */
        #chat-history::-webkit-scrollbar { width: 8px; }
        #chat-history::-webkit-scrollbar-thumb { background-color: #cbd5e1; border-radius: 4px; }
        
        /* Loading dots animation */
        @keyframes dot-flashing {
            0% { background-color: #f3f4f6; }
            50%, 100% { background-color: #4ba276; }
        }
        .dot-flashing {
            animation: dot-flashing 1s infinite alternate;
        }
        .dot-flashing:nth-child(2) { animation-delay: 0.3s; }
        .dot-flashing:nth-child(3) { animation-delay: 0.6s; }
        
        /* Message bubble styles */
        .user-bubble {
            background-color: #d1fae5; /* green-100 */
            align-self: flex-end;
            /* Pointed corner on the bottom-right (sender side) */
            border-radius: 24px 24px 4px 24px;
        }
        .ai-bubble {
            background-color: #f3f4f6; /* gray-100 */
            align-self: flex-start;
            /* Pointed corner on the bottom-left (receiver side) */
            border-radius: 24px 24px 24px 4px;
        }
    </style>
</head>
<body class="bg-primary-bg min-h-screen flex items-center justify-center p-4">

    <!-- Main Container -->
    <div id="main-container" class="w-full max-w-lg bg-secondary-bg rounded-xl shadow-2xl overflow-hidden flex flex-col min-h-[90vh]">
        
        <!-- Header -->
        <header class="bg-chamsi-green text-white p-4 flex justify-between items-center shadow-lg">
            <h1 class="text-xl font-bold">Chamsi AI</h1>
            <div id="auth-controls">
                <button id="logout-btn" onclick="logout()" class="hidden bg-chamsi-red hover:bg-opacity-90 transition-colors text-white text-sm py-1 px-3 rounded-lg shadow-md">
                    Logout
                </button>
            </div>
        </header>

        <!-- Dynamic Content Area -->
        <div id="content-area" class="flex-grow p-4 overflow-y-auto">
            
            <!-- Auth Forms (Initial View) -->
            <div id="auth-view" class="h-full flex flex-col justify-center items-center text-center">
                <div id="login-form" class="w-full max-w-sm p-6 bg-white rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">Login</h2>
                    <form onsubmit="handleAuth(event, 'login')">
                        <input id="login-email" type="email" placeholder="Email" required 
                               class="w-full p-3 mb-4 border border-gray-300 rounded-lg focus:ring-chamsi-green focus:border-chamsi-green">
                        <input id="login-password" type="password" placeholder="Password" required 
                               class="w-full p-3 mb-6 border border-gray-300 rounded-lg focus:ring-chamsi-green focus:border-chamsi-green">
                        <button type="submit" class="w-full py-3 bg-chamsi-green text-white font-semibold rounded-lg hover:bg-opacity-90 transition-colors shadow-md">
                            Sign In
                        </button>
                    </form>
                    <p class="mt-4 text-sm text-gray-600">
                        Don't have an account? 
                        <a href="#" onclick="showRegisterForm(event)" class="text-chamsi-green font-medium hover:underline">Sign Up</a>
                    </p>
                    <p id="login-message" class="mt-4 text-red-500 font-medium"></p>
                </div>

                <div id="register-form" class="hidden w-full max-w-sm p-6 bg-white rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">Register</h2>
                    <form onsubmit="handleAuth(event, 'register')">
                        <input id="register-email" type="email" placeholder="Email" required 
                               class="w-full p-3 mb-4 border border-gray-300 rounded-lg focus:ring-chamsi-green focus:border-chamsi-green">
                        <input id="register-password" type="password" placeholder="Password (min 8 chars)" required 
                               class="w-full p-3 mb-6 border border-gray-300 rounded-lg focus:ring-chamsi-green focus:border-chamsi-green">
                        <button type="submit" class="w-full py-3 bg-chamsi-green text-white font-semibold rounded-lg hover:bg-opacity-90 transition-colors shadow-md">
                            Sign Up
                        </button>
                    </form>
                    <p class="mt-4 text-sm text-gray-600">
                        Already have an account? 
                        <a href="#" onclick="showLoginForm(event)" class="text-chamsi-green font-medium hover:underline">Sign In</a>
                    </p>
                    <p id="register-message" class="mt-4 text-red-500 font-medium"></p>
                </div>
            </div>

            <!-- Chat Interface (Hidden by default) -->
            <div id="chat-view" class="hidden h-full flex flex-col">
                <!-- Chat History Area -->
                <div id="chat-history" class="flex-grow overflow-y-auto space-y-4 p-2 pb-4">
                    <div class="ai-bubble p-3 rounded-xl max-w-xs md:max-w-md shadow-md text-gray-700">
                        <strong class="text-chamsi-green">Chamsi AI:</strong> Welcome! Please feel free to ask me anything.
                    </div>
                </div>
            </div>
            
        </div>

        <!-- Input Area (Only visible when logged in) -->
        <footer id="input-footer" class="hidden p-4 border-t border-gray-200">
            <div class="flex items-end space-x-3">
                <textarea 
                    id="prompt-input" 
                    rows="1" 
                    placeholder="Ask Chamsi anything..." 
                    oninput="autoResize(this)" 
                    onkeydown="handleKeyDown(event)"
                    class="flex-grow resize-none p-3 border border-gray-300 rounded-xl focus:ring-chamsi-green focus:border-chamsi-green text-gray-800 transition-shadow"
                    style="max-height: 200px;"
                ></textarea>
                <button 
                    id="submit-btn" 
                    onclick="submitPrompt()" 
                    class="p-3 bg-chamsi-green text-white rounded-xl shadow-md hover:bg-opacity-90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-shrink-0"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-send">
                        <path d="m22 2-7 20-4-9-9-4Z"/>
                        <path d="M22 2 11 13"/>
                    </svg>
                </button>
            </div>
        </footer>

    </div>

    <script>
        // Use the Flask-provided URL
        const API_BASE_URL = "{{ ai_server_url }}";
        
        // --- Client-Side State Management ---
        let userState = {
            token: localStorage.getItem('chamsi_jwt') || null,
            userId: localStorage.getItem('chamsi_user_id') || null,
        };

        // --- UI State Handlers ---
        
        function showAuthView(messageId, message) {
            document.getElementById(messageId).textContent = message;
            setTimeout(() => { document.getElementById(messageId).textContent = ''; }, 3000);
        }

        function showLoginForm(e) {
            if (e) e.preventDefault();
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('login-form').classList.remove('hidden');
        }

        function showRegisterForm(e) {
            if (e) e.preventDefault();
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.remove('hidden');
        }

        function updateUI() {
            if (userState.token) {
                // Logged in view
                document.getElementById('auth-view').classList.add('hidden');
                document.getElementById('chat-view').classList.remove('hidden');
                document.getElementById('input-footer').classList.remove('hidden');
                document.getElementById('logout-btn').classList.remove('hidden');
            } else {
                // Logged out view
                document.getElementById('auth-view').classList.remove('hidden');
                document.getElementById('chat-view').classList.add('hidden');
                document.getElementById('input-footer').classList.add('hidden');
                document.getElementById('logout-btn').classList.add('hidden');
                showLoginForm(); // Default back to login
            }
        }
        
        // --- Authentication Logic (Client) ---

        async function handleAuth(event, type) {
            event.preventDefault();
            const formPrefix = type; // 'login' or 'register'
            const email = document.getElementById(`${formPrefix}-email`).value.trim();
            const password = document.getElementById(`${formPrefix}-password`).value.trim();
            const messageBoxId = `${formPrefix}-message`;

            if (!email || !password) {
                showAuthView(messageBoxId, "Please fill in both fields.");
                return;
            }

            const url = `${API_BASE_URL}/api/${type}`;
            const button = event.target.querySelector('button[type="submit"]');
            
            button.disabled = true;
            showAuthView(messageBoxId, "Processing...");

            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();
                
                if (response.ok) {
                    showAuthView(messageBoxId, `${type} successful!`);
                    // Store token and user ID
                    userState.token = data.token;
                    userState.userId = data.user_id;
                    localStorage.setItem('chamsi_jwt', data.token);
                    localStorage.setItem('chamsi_user_id', data.user_id);
                    updateUI();
                } else {
                    showAuthView(messageBoxId, data.message || `Failed to ${type}.`);
                }
            } catch (error) {
                console.error('Auth error:', error);
                showAuthView(messageBoxId, 'Network error. Could not reach server.');
            } finally {
                button.disabled = false;
            }
        }

        function logout() {
            userState.token = null;
            userState.userId = null;
            localStorage.removeItem('chamsi_jwt');
            localStorage.removeItem('chamsi_user_id');
            // Clear chat history on logout for security
            document.getElementById('chat-history').innerHTML = `
                <div class="ai-bubble p-3 rounded-xl max-w-xs md:max-w-md shadow-md text-gray-700">
                    <strong class="text-chamsi-green">Chamsi AI:</strong> You have been logged out. Please sign in to continue.
                </div>
            `;
            updateUI();
        }


        // --- Chat UI Helpers ---
        
        function autoResize(textarea) {
            textarea.style.height = 'auto';
            textarea.style.height = textarea.scrollHeight + 'px';
        }

        function appendMessage(role, text) {
            const chatHistory = document.getElementById('chat-history');
            const isUser = role === 'user';
            
            const messageDiv = document.createElement('div');
            messageDiv.className = `p-3 rounded-xl max-w-xs md:max-w-md shadow-md text-gray-700 whitespace-pre-wrap ${isUser ? 'user-bubble ml-auto' : 'ai-bubble mr-auto'}`;
            messageDiv.innerHTML = `<strong>${isUser ? 'You' : 'Chamsi AI'}:</strong> ${text}`;
            
            chatHistory.appendChild(messageDiv);
            chatHistory.scrollTop = chatHistory.scrollHeight; // Scroll to bottom
            return messageDiv;
        }

        function createLoadingIndicator() {
            const chatHistory = document.getElementById('chat-history');
            const loadingDiv = document.createElement('div');
            loadingDiv.id = 'loading-indicator';
            loadingDiv.className = 'ai-bubble p-3 rounded-xl max-w-xs md:max-w-md shadow-md flex space-x-1';
            
            loadingDiv.innerHTML = `
                <div class="w-2 h-2 rounded-full dot-flashing"></div>
                <div class="w-2 h-2 rounded-full dot-flashing"></div>
                <div class="w-2 h-2 rounded-full dot-flashing"></div>
            `;
            chatHistory.appendChild(loadingDiv);
            chatHistory.scrollTop = chatHistory.scrollHeight;
        }

        function removeLoadingIndicator() {
            const loadingDiv = document.getElementById('loading-indicator');
            if (loadingDiv) {
                loadingDiv.remove();
            }
        }

        // --- Gemini Interaction Logic (Client) ---

        async function getGeminiResponse(prompt) {
            const url = `${API_BASE_URL}/api/generate`;
            const token = userState.token;

            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}` // Send the JWT token
                    },
                    body: JSON.stringify({ prompt })
                });

                const data = await response.json();

                if (response.ok) {
                    let fullText = data.response;
                    
                    if (data.sources && data.sources.length > 0) {
                        const citationHtml = data.sources.map((src, index) => 
                            `<a href="${src.uri}" target="_blank" class="text-xs text-chamsi-green hover:underline"> [${index + 1}] ${src.title}</a>`
                        ).join(' ');
                        fullText += `\\n\\n---\\nCitations: ${citationHtml}`;
                    }

                    return fullText;

                } else if (response.status === 401) {
                    logout(); // Force logout if token is expired or invalid
                    return `Your session has expired or is invalid. Please log in again.`;
                } else {
                    return `Error: ${data.message || 'Failed to get response from AI server.'}`;
                }

            } catch (error) {
                console.error('Network error during AI call:', error);
                return 'Network Error: Could not reach the AI server.';
            }
        }

        window.submitPrompt = async function() {
            const input = document.getElementById('prompt-input');
            const submitBtn = document.getElementById('submit-btn');
            const prompt = input.value.trim();

            if (!userState.token) { return; } // Should not happen, but a guard
            if (!prompt) { return; }

            // 1. Disable input and show user message
            input.value = '';
            autoResize(input);
            submitBtn.disabled = true;
            appendMessage('user', prompt);
            createLoadingIndicator();

            // 2. Get AI Response
            const aiResponse = await getGeminiResponse(prompt);

            // 3. Remove loading and display AI response
            removeLoadingIndicator();
            appendMessage('ai', aiResponse);
            submitBtn.disabled = false;
            input.focus();
        }

        window.handleKeyDown = function(event) {
            // Check for Shift + Enter for new line, or just Enter to submit
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault(); // Prevents adding a new line
                submitPrompt();
            }
        }
        
        // --- Initialization ---
        window.onload = function() {
            updateUI(); // Check local storage on load and update view
        };

        // Expose functions for HTML calls
        window.handleAuth = handleAuth;
        window.showLoginForm = showLoginForm;
        window.showRegisterForm = showRegisterForm;
        window.logout = logout;
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    host = os.getenv('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_RUN_PORT', 3000))
    print("--- Chamsi AI Full Stack Application Setup ---")
    print(f"Flask Host: {host}, Port: {port}")
    print("1. Set up your MySQL database using 'chamsi_full_setup.sql'.")
    print("2. Make sure you have updated the connection details in the '.env' file.")
    print("3. Run this Python file: python chamsi_full_app.py")
    print(f"Web interface available at: http://{host}:{port}/")
    
    # Run the Flask app
    app.run(host=host, port=port, debug=True)