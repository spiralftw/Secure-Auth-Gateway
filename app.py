# =============================================================================
# app.py — Main Application
# =============================================================================
#
# This is the entry point of the Secure Auth Gateway. It uses Flask, a
# lightweight Python web framework. Flask listens for incoming HTTP requests
# and routes them to the appropriate handler function based on the URL path.
#
# HOW FLASK ROUTING WORKS:
#   @app.route("/login", methods=["GET", "POST"])
#   def login():
#       ...
#
#   The @app.route decorator tells Flask: "when a request arrives for /login,
#   call the login() function." The methods list specifies which HTTP methods
#   are allowed — GET is for loading a page, POST is for submitting a form.
#
# SECURITY FEATURES IMPLEMENTED IN THIS FILE:
#   1. Honeypot field detection    — catches automated bots
#   2. Rate limiting               — prevents brute-force attacks
#   3. Timing-safe login           — prevents user enumeration via timing
#   4. MFA / TOTP support          — two-factor authentication
#   5. OAuth 2.0 (GitHub SSO)      — third-party login with CSRF protection
#   6. Security event logging      — all suspicious activity is recorded

import os
import secrets
import warnings
from datetime import datetime, timedelta
from collections import defaultdict

# Load environment variables from a .env file if it exists.
# This allows you to set ENCRYPTION_KEY, SECRET_KEY, etc. in a file
# instead of typing them in the terminal every time.
# If python-dotenv is not installed, we silently fall back to system env vars.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import (
    Flask, request, jsonify, render_template,
    session, url_for, redirect
)
from authlib.deprecate import AuthlibDeprecationWarning
with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore",
        category=AuthlibDeprecationWarning,
        message=r"authlib\.jose module is deprecated, please use joserfc instead\.",
    )
    from authlib.integrations.flask_client import OAuth

from database import db, User, SecurityLog
from auth import hash_password, verify_password
from encryption import encrypt, decrypt
from mfa import generate_secret, verify_code, get_qr_uri, get_qr_code_base64


# =============================================================================
# Application Setup
# =============================================================================

app = Flask(__name__)

# The secret key is used to cryptographically sign the session cookie.
# If an attacker doesn't know this key, they cannot forge a valid session.
# We load it from the environment; if it's missing, we generate a random
# one at startup (which means all sessions are invalidated on restart —
# fine for development, but set a fixed key in production).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Database URI. SQLite stores everything in a single local file.
# For production, switch to PostgreSQL by setting DATABASE_URL in .env.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///database.sqlite"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Suppresses a deprecation warning

# Attach the SQLAlchemy database object to the Flask app.
db.init_app(app)

# Create all database tables on startup if they don't already exist.
# This is safe to run repeatedly — it only creates tables that are missing.
with app.app_context():
    db.create_all()


# =============================================================================
# OAuth Setup (GitHub SSO)
# =============================================================================

oauth = OAuth(app)

# Register GitHub as an OAuth provider.
# To use this, you must create an OAuth App at:
#   https://github.com/settings/developers
# Set the callback URL to: http://localhost:5000/oauth/github/callback
# Then add GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET to your .env file.
oauth.register(
    name="github",
    client_id=os.environ.get("GITHUB_CLIENT_ID"),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)


# =============================================================================
# Rate Limiting
# =============================================================================
#
# Rate limiting prevents brute-force attacks by capping how many login
# attempts are allowed from a single IP address within a time window.
#
# We store a list of attempt timestamps per IP in memory:
#   { "192.168.1.1": [datetime(...), datetime(...), ...] }
#
# For production, replace this with Redis so limits survive restarts.

_login_attempts: dict = defaultdict(list)  # { ip: [timestamp, ...] }

MAX_ATTEMPTS    = 5   # Maximum allowed attempts before blocking
WINDOW_MINUTES  = 15  # Time window in minutes


def is_rate_limited(ip: str) -> bool:
    """
    Check whether an IP address has exceeded the login attempt limit.

    Returns True (blocked) if the IP has made MAX_ATTEMPTS or more
    attempts within the last WINDOW_MINUTES minutes.
    """
    now          = datetime.utcnow()
    window_start = now - timedelta(minutes=WINDOW_MINUTES)

    # Discard timestamps that are outside the current time window.
    _login_attempts[ip] = [
        t for t in _login_attempts[ip] if t > window_start
    ]

    return len(_login_attempts[ip]) >= MAX_ATTEMPTS


def record_attempt(ip: str) -> None:
    """Record a new login attempt for the given IP address."""
    _login_attempts[ip].append(datetime.utcnow())


# =============================================================================
# Security Event Logging
# =============================================================================

def log_security_event(ip: str, action: str, email: str = None) -> None:
    """
    Write a security event to the SecurityLog table.

    This is called whenever something suspicious happens:
      - A honeypot field is filled (bot detected)
      - Rate limit is exceeded (brute force attempt)
      - A login attempt fails
    """
    entry = SecurityLog(ip_address=ip, action=action, email=email)
    db.session.add(entry)
    db.session.commit()


# =============================================================================
# Helper: Get Currently Logged-In User
# =============================================================================

def get_current_user():
    """
    Look up the currently authenticated user from the session.

    Flask's session is a signed cookie. We store only the user's ID in
    it — never the full user object — to keep the cookie small and to
    ensure we always get fresh data from the database.

    Returns the User object if logged in, or None if not.
    """
    user_id = session.get("user_id")
    if not user_id:
        return None
    # db.session.get() is the modern SQLAlchemy 2.x way to fetch by primary key.
    return db.session.get(User, user_id)


# =============================================================================
# Route: Home
# =============================================================================

@app.route("/")
def home():
    """
    Home page with options to register or login.
    If already logged in, redirect to dashboard.
    """
    user = get_current_user()
    if user:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


# =============================================================================
# Route: Register
# =============================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    GET  — Serve the registration form.
    POST — Process the submitted form and create a new user account.
    """
    if request.method == "GET":
        return render_template("register.html")

    # --- Collect form data ---
    ip       = request.remote_addr
    email    = request.form.get("email",    "").strip().lower()
    password = request.form.get("password", "")

    # --- Honeypot check ---
    # The registration form contains a hidden field called "website".
    # Real users never see it (it's hidden with CSS) and therefore never
    # fill it in. Automated bots that blindly fill all form fields will
    # populate it. If it is non-empty, we know with certainty it's a bot.
    if request.form.get("website"):
        log_security_event(ip, "HONEYPOT_TRIGGERED", email)
        # Return a generic error — never tell the bot it was detected.
        return jsonify({"error": "Registration failed."}), 400

    # --- Basic input validation ---
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    # --- Check for duplicate email ---
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with this email already exists."}), 409

    # --- Hash the password and create the user ---
    # hash_password() calls Argon2id internally — the plaintext password
    # is never stored anywhere after this point.
    hashed = hash_password(password)
    user   = User(email=email, password_hash=hashed)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Registration successful!", "user_id": user.id}), 201


# =============================================================================
# Route: Login
# =============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET  — Serve the login form.
    POST — Validate credentials and start a session (or redirect to MFA).
    """
    if request.method == "GET":
        return render_template("login.html")

    ip       = request.remote_addr
    email    = request.form.get("email",    "").strip().lower()
    password = request.form.get("password", "")

    # --- Honeypot check ---
    if request.form.get("website"):
        log_security_event(ip, "HONEYPOT_TRIGGERED", email)
        return jsonify({"error": "Invalid credentials."}), 401

    # --- Rate limiting check ---
    # Block IPs that have made too many failed attempts recently.
    if is_rate_limited(ip):
        log_security_event(ip, "RATE_LIMIT_EXCEEDED", email)
        return jsonify({
            "error": f"Too many login attempts. Please wait {WINDOW_MINUTES} minutes."
        }), 429

    # Record this attempt BEFORE checking the password, so failed attempts
    # are always counted even if we return early.
    record_attempt(ip)

    # --- Fetch user from database ---
    user = User.query.filter_by(email=email).first()

    # --- Timing-safe password check ---
    # IMPORTANT: We always call verify_password(), even if the user was not
    # found. If we returned early when the user doesn't exist, an attacker
    # could measure the response time to determine whether an email is
    # registered (faster response = no user found). Using a dummy hash
    # ensures the response time is the same either way.
    _DUMMY_HASH = (
        "$argon2id$v=19$m=65536,t=3,p=4"
        "$c29tZXNhbHRzb21lc2FsdA"
        "$7W/fRuOQQpfbOGMJoEGRMIJl6JDQmKJ1S8SRFIH5TMo"
    )
    hash_to_check = user.password_hash if user else _DUMMY_HASH
    password_ok   = verify_password(password, hash_to_check)

    if not user or not password_ok:
        log_security_event(ip, "LOGIN_FAILURE", email)
        # Use the same error message whether the email or the password is wrong.
        # Different messages would allow attackers to enumerate valid accounts.
        return jsonify({"error": "Invalid email or password."}), 401

    # --- MFA check ---
    # If the user has two-factor authentication enabled, we don't complete
    # the login here. We store a temporary "pending" flag in the session
    # and tell the client to redirect to the MFA verification page.
    if user.mfa_enabled:
        session["pending_mfa_user_id"] = user.id
        return jsonify({"mfa_required": True, "redirect": "/mfa/verify"}), 200

    # --- Login successful ---
    session["user_id"] = user.id
    return jsonify({"message": f"Welcome, {user.email}!"}), 200


# =============================================================================
# Route: MFA Setup
# =============================================================================

@app.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    """
    GET  — Generate a new TOTP seed, encrypt it, save it, and show the QR code.
    POST — Verify the user's first code to confirm the setup worked.

    MFA is NOT activated until the user successfully verifies a code.
    This prevents the user from being locked out if they abandon setup halfway.
    """
    user = get_current_user()
    if not user:
        return jsonify({"error": "You must be logged in to set up MFA."}), 401

    if request.method == "GET":
        # Step 1: Generate a fresh random TOTP seed.
        secret = generate_secret()

        # Step 2: Encrypt the seed before storing it in the database.
        # If the database leaks, an attacker will only see AES-256-GCM
        # ciphertext — useless without the ENCRYPTION_KEY.
        enc_secret, iv = encrypt(secret)

        # Step 3: Save the encrypted seed. mfa_enabled stays False
        # until the user confirms the setup with a valid code.
        user.mfa_secret_enc = enc_secret
        user.mfa_iv         = iv
        db.session.commit()

        # Step 4: Build the QR code URI and render it as a base64 PNG
        # so it can be displayed inline in the HTML page.
        uri    = get_qr_uri(secret, user.email)
        qr_b64 = get_qr_code_base64(uri)

        return render_template("mfa_setup.html", qr_b64=qr_b64)

    # POST: the user has scanned the QR code and submits their first code.
    code = request.form.get("code", "").strip()

    # Decrypt the seed so we can verify the submitted code.
    secret = decrypt(user.mfa_secret_enc, user.mfa_iv)

    if not verify_code(secret, code):
        return jsonify({"error": "Incorrect code. Please try again."}), 400

    # The code is correct — activate MFA for this user.
    user.mfa_enabled = True
    db.session.commit()

    return jsonify({"message": "Two-factor authentication has been enabled!"}), 200


# =============================================================================
# Route: MFA Verification (during login)
# =============================================================================

@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    """
    GET  — Show the code entry form.
    POST — Validate the submitted TOTP code and complete the login.

    This route is reached after a successful password check when the user
    has MFA enabled. The session holds a "pending_mfa_user_id" to identify
    which user is in the middle of logging in.
    """
    pending_id = session.get("pending_mfa_user_id")
    if not pending_id:
        return jsonify({"error": "No pending login session found."}), 401

    if request.method == "GET":
        return render_template("mfa_verify.html")

    code = request.form.get("code", "").strip()
    user = db.session.get(User, pending_id)

    if not user:
        return jsonify({"error": "User not found."}), 404

    # Decrypt the stored TOTP seed and verify the submitted code.
    secret = decrypt(user.mfa_secret_enc, user.mfa_iv)

    if not verify_code(secret, code):
        return jsonify({"error": "Incorrect code. Please try again."}), 401

    # Code is correct — finalize the login.
    # Remove the temporary pending key and set the real user_id.
    session.pop("pending_mfa_user_id", None)
    session["user_id"] = user.id

    return jsonify({"message": f"Welcome, {user.email}!"}), 200


# =============================================================================
# Route: OAuth Login (GitHub)
# =============================================================================

@app.route("/oauth/<provider>/login")
def oauth_login(provider):
    """
    Redirect the user to the OAuth provider's authorization page.

    This is step 1 of the OAuth 2.0 Authorization Code Flow:
      1. We generate a random "state" token and store it in the session.
      2. We redirect the user to GitHub, including the state token.
      3. GitHub authenticates the user and redirects back to /callback.
      4. We verify the returned state matches the one we stored (CSRF check).
      5. We exchange the authorization code for an access token.
      6. We use the token to fetch the user's email from GitHub's API.

    The state parameter is CSRF (Cross-Site Request Forgery) protection.
    Without it, an attacker could trick the user's browser into completing
    an OAuth flow that the attacker initiated, linking the victim's account
    to the attacker's GitHub identity.
    """
    if provider not in ("github",):
        return jsonify({"error": "Unknown OAuth provider."}), 400

    # Generate a cryptographically random, URL-safe state token.
    state = secrets.token_urlsafe(32)

    # Store it in the session so we can verify it in the callback.
    session["oauth_state"] = state

    # Build the callback URL and redirect the user to GitHub.
    callback_url = url_for("oauth_callback", provider=provider, _external=True)
    return oauth.github.authorize_redirect(callback_url, state=state)


@app.route("/oauth/<provider>/callback")
def oauth_callback(provider):
    """
    Handle the redirect back from the OAuth provider after authentication.
    """
    if provider not in ("github",):
        return jsonify({"error": "Unknown OAuth provider."}), 400

    # --- CSRF Check ---
    # Compare the state returned by GitHub to the one we stored in the session.
    # If they differ, this callback was not initiated by our app — reject it.
    returned_state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)

    if not returned_state or returned_state != expected_state:
        return jsonify({"error": "Invalid state parameter — possible CSRF attack."}), 403

    # Exchange the authorization code (in the callback URL) for an access token.
    # This request is made server-to-server, so the token never touches the browser.
    token = oauth.github.authorize_access_token()

    # Use the access token to call GitHub's API and get the user's profile.
    github_user = oauth.github.get("user", token=token).json()

    # GitHub may not include the email in the /user response if it is set to
    # private. Fetch the /user/emails endpoint to get the primary email.
    emails       = oauth.github.get("user/emails", token=token).json()
    primary_email = next(
        (e["email"] for e in emails if e.get("primary") and e.get("verified")),
        github_user.get("email")
    )

    github_id = str(github_user["id"])

    # Check if we already have a local account for this GitHub user.
    user = User.query.filter_by(oauth_provider="github", oauth_id=github_id).first()

    if not user:
        # First time this GitHub account has logged in — create a local account.
        # OAuth users have no password_hash (they never set one).
        user = User(
            email          = primary_email,
            oauth_provider = "github",
            oauth_id       = github_id,
        )
        db.session.add(user)
        db.session.commit()

    # Log the user in.
    session["user_id"] = user.id
    return redirect(url_for("dashboard"))


# =============================================================================
# Route: Logout
# =============================================================================

@app.route("/logout")
def logout():
    """Clear the session, effectively logging the user out."""
    session.clear()
    return redirect(url_for("home"))


# =============================================================================
# Route: Dashboard (example protected page)
# =============================================================================

@app.route("/dashboard")
def dashboard():
    """
    A simple protected page — only accessible when logged in.
    Demonstrates how to check authentication in a route.
    """
    user = get_current_user()
    if not user:
        # Redirect unauthenticated users to the login page.
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


# =============================================================================
# Application Entry Point
# =============================================================================

if __name__ == "__main__":
    # debug=True enables auto-reload on code changes and shows detailed error
    # pages in the browser. NEVER use debug=True in production — it exposes
    # an interactive Python console that can execute arbitrary code.
    app.run(debug=True)
