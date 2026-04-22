"""
auth_app.py — Flask Auth System with PostgreSQL
================================================
Stack : Flask + psycopg2 + Werkzeug password hashing
Auth  : Session-based login + Role-Based Access Control (RBAC)
DB    : PostgreSQL  (users table)

Quick start
-----------
1. pip install flask psycopg2-binary werkzeug python-dotenv
2. Create a .env file (see .env.example below)
3. python auth_app.py          ← creates the table & seeds demo users
4. Visit http://127.0.0.1:5000

.env.example
------------
DATABASE_URL=postgresql://postgres:password@localhost:5432/auth_demo
SECRET_KEY=change-me-in-production
"""

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════════════════════

import os
import secrets
from contextlib import contextmanager
from functools import wraps

import psycopg2                        # PostgreSQL driver
import psycopg2.extras                 # RealDictCursor → rows as dicts
from dotenv import load_dotenv
from flask import (Flask, Response, flash, redirect,
                   render_template_string, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()   # reads .env file into os.environ


# ══════════════════════════════════════════════════════════════════════════════
# 1. APP CONFIGURATION
#    secret_key  – signs the session cookie (HMAC); tampering invalidates it.
#    HTTPONLY    – JavaScript cannot read the cookie (XSS protection).
#    SAMESITE    – cookie is not sent with cross-site requests (CSRF protection).
#    SECURE      – cookie is only sent over HTTPS (set True in production).
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    SESSION_COOKIE_SECURE   = False,   # ← True in production
)


# ══════════════════════════════════════════════════════════════════════════════
# 2. DATABASE LAYER
#
#    get_db_conn()  — returns a raw psycopg2 connection.
#    db_cursor()    — context manager; opens a RealDictCursor, auto-commits
#                     on success and rolls back on any exception.
#
#    Why RealDictCursor?
#    Regular psycopg2 returns rows as tuples: row[0], row[1] …
#    RealDictCursor returns rows as dicts:   row["id"], row["username"] …
#    Much easier to read and less error-prone.
# ══════════════════════════════════════════════════════════════════════════════

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/auth_demo"   # fallback default
)


def get_db_conn():
    """
    Open and return a new psycopg2 connection.
    sslmode='prefer' works locally and on hosted Postgres (Render, Supabase …).
    """
    return psycopg2.connect(DATABASE_URL, sslmode="prefer")


@contextmanager
def db_cursor():
    """
    Context manager that gives you a RealDictCursor and handles
    commit / rollback automatically.

    Usage:
        with db_cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
            row = cur.fetchone()   # → {"id": 1, "username": "admin", …}
    """
    conn = get_db_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit()                  # ← auto-commit if no exception
    except Exception:
        conn.rollback()                # ← auto-rollback on any error
        raise
    finally:
        conn.close()                   # ← always close the connection


# ══════════════════════════════════════════════════════════════════════════════
# 3. DATABASE INITIALISATION
#    init_db() runs once at startup:
#      a) Creates the `users` table if it does not exist yet.
#      b) Seeds three demo accounts (admin, alice, bob).
#         INSERT … ON CONFLICT DO NOTHING makes it safe to call repeatedly.
#
#    users table schema
#    ------------------
#    id         SERIAL PRIMARY KEY        — auto-incrementing integer
#    username   VARCHAR(80) UNIQUE        — login name, must be unique
#    password   TEXT                      — Werkzeug hash (never plain text)
#    role       VARCHAR(20) DEFAULT 'user'— 'admin' or 'user'
#    created_at TIMESTAMP DEFAULT NOW()  — when the account was created
# ══════════════════════════════════════════════════════════════════════════════

def init_db():
    """Create tables and seed demo users. Safe to call on every startup."""
    with db_cursor() as cur:

        # ── Create users table ────────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         SERIAL      PRIMARY KEY,
                username   VARCHAR(80) NOT NULL UNIQUE,
                password   TEXT        NOT NULL,
                role       VARCHAR(20) NOT NULL DEFAULT 'user'
                               CHECK (role IN ('admin', 'user')),
                created_at TIMESTAMP   NOT NULL DEFAULT NOW()
            );
        """)

        # ── Seed demo accounts ────────────────────────────────────────────────
        # ON CONFLICT (username) DO NOTHING → skipped if the user already exists
        demo_users = [
            ("admin", generate_password_hash("admin123"), "admin"),
            ("alice", generate_password_hash("alice123"), "user"),
            ("bob",   generate_password_hash("bob123"),   "user"),
        ]
        cur.executemany(
            """
            INSERT INTO users (username, password, role)
            VALUES (%s, %s, %s)
            ON CONFLICT (username) DO NOTHING
            """,
            demo_users,
        )

    print("  [DB] Table 'users' ready. Demo accounts seeded.")


# ══════════════════════════════════════════════════════════════════════════════
# 4. USER QUERIES
#    Small, focused functions — each does exactly one DB operation.
#    Using %s placeholders (never f-strings) prevents SQL injection.
# ══════════════════════════════════════════════════════════════════════════════

def get_user_by_username(username: str) -> dict | None:
    """
    SELECT a user row by username.
    Returns a dict like {"id": 1, "username": "admin", "password": "...", "role": "admin"}
    or None if not found.
    """
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, username, password, role FROM users WHERE username = %s",
            (username,),      # ← always a tuple — prevents SQL injection
        )
        return cur.fetchone()   # RealDictRow or None


def get_user_by_id(user_id: int) -> dict | None:
    """SELECT a user row by primary key (used to refresh session data)."""
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, username, role FROM users WHERE id = %s",
            (user_id,),
        )
        return cur.fetchone()


def get_all_users() -> list[dict]:
    """SELECT all users — admin panel only."""
    with db_cursor() as cur:
        cur.execute("SELECT id, username, role, created_at FROM users ORDER BY id")
        return cur.fetchall()


def create_user(username: str, password: str, role: str = "user") -> dict:
    """
    INSERT a new user and return the created row.
    The password is hashed here so callers never touch raw hashes.
    Raises psycopg2.errors.UniqueViolation if username already exists.
    """
    hashed = generate_password_hash(password)
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (username, password, role)
            VALUES (%s, %s, %s)
            RETURNING id, username, role
            """,
            (username, hashed, role),
        )
        return cur.fetchone()


# ══════════════════════════════════════════════════════════════════════════════
# 5. ACCESS CONTROL DECORATORS
#
#    @login_required   — user must be logged in  (any role)
#    @admin_required   — user must have role = "admin"
#
#    @wraps(f) copies __name__ and __doc__ from the original function.
#    Without it, Flask would see two routes named "decorated" and crash.
# ══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    """
    Redirect to /login if the user has no active session.
    Preserves the original URL in ?next= so the user returns after login.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Returns HTTP 403 Forbidden if the logged-in user is not an admin.
    Stacks on top of login_required logic — checks both auth AND role.

    HTTP 403 vs 302 redirect:
    - 403 tells the browser (and APIs) that access is denied, not that
      the user needs to authenticate. Correct semantic for RBAC.
    - 302 redirect to login would be wrong — the user IS logged in,
      they just lack the required role.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            return Response(TEMPLATE_403, status=403, mimetype="text/html")
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════════════════
# 6. CURRENT USER HELPER
#    Reads user_id from session and fetches the row from PostgreSQL.
#    Called in templates to get name, role, etc.
# ══════════════════════════════════════════════════════════════════════════════

def current_user() -> dict | None:
    uid = session.get("user_id")
    return get_user_by_id(uid) if uid else None


# ══════════════════════════════════════════════════════════════════════════════
# 7. ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Public landing page — no auth required."""
    return render_template_string(TEMPLATE_HOME, user=current_user())


# ── /login ────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET  → render the login form.
    POST → validate credentials against PostgreSQL, write session, redirect.

    Login flow:
      1. Read username + password from the form.
      2. Look up the username in the DB  (get_user_by_username).
      3. check_password_hash() verifies the submitted password against
         the stored bcrypt hash — timing-safe, brute-force resistant.
      4. On success: write user_id and role into the signed session cookie.
      5. Redirect to ?next= (original page) or /dashboard.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        # ── Step 1: fetch the user row from PostgreSQL ────────────────────────
        user = get_user_by_username(username)

        # ── Step 2: verify the password hash ──────────────────────────────────
        # check_password_hash is timing-safe:
        # it always takes the same time regardless of whether the hash matches,
        # preventing timing-based username enumeration attacks.
        if user and check_password_hash(user["password"], password):

            # ── Step 3: write session ──────────────────────────────────────────
            session.clear()                        # clear any leftover data
            session["user_id"]  = user["id"]       # int — used to fetch user
            session["role"]     = user["role"]     # str — used by decorators
            session["username"] = user["username"] # str — display only
            session.permanent   = False            # ends when browser closes

            flash(f"Welcome back, {user['username']}!", "success")
            next_page = request.args.get("next") or url_for("dashboard")
            return redirect(next_page)

        else:
            # Deliberately vague error — don't reveal whether username exists
            flash("Invalid username or password.", "danger")

    return render_template_string(TEMPLATE_LOGIN, alerts=_alerts())


# ── /logout ───────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    """
    Destroy the session completely.
    session.clear() removes ALL keys from the signed cookie.
    After this call, every @login_required route will redirect to /login.
    """
    username = session.get("username", "User")
    session.clear()
    flash(f"Goodbye, {username}. You have been logged out.", "info")
    return redirect(url_for("login"))


# ── /dashboard ────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required          # ← any authenticated user (admin or user)
def dashboard():
    """
    Regular user dashboard.
    Protected by @login_required — anonymous users are redirected to /login.
    Both 'user' and 'admin' roles can access this page.
    """
    return render_template_string(TEMPLATE_DASHBOARD, user=current_user())


# ── /admin ────────────────────────────────────────────────────────────────────
@app.route("/admin")
@admin_required          # ← only role == "admin"
def admin():
    """
    Admin-only dashboard.
    Protected by @admin_required — non-admins receive HTTP 403 Forbidden.
    Queries all users from PostgreSQL for the management table.
    """
    return render_template_string(
        TEMPLATE_ADMIN,
        user=current_user(),
        all_users=get_all_users(),
    )


# ── /register (bonus — admin only) ───────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
@admin_required
def register():
    """
    Admin can create new user accounts.
    Demonstrates create_user() and duplicate-username handling.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        role     = request.form.get("role", "user")

        if not username or not password:
            flash("Username and password are required.", "danger")
        elif role not in ("admin", "user"):
            flash("Invalid role.", "danger")
        else:
            try:
                new_user = create_user(username, password, role)
                flash(f"User '{new_user['username']}' created with role '{new_user['role']}'.", "success")
                return redirect(url_for("admin"))
            except Exception as e:
                if "unique" in str(e).lower():
                    flash(f"Username '{username}' is already taken.", "danger")
                else:
                    flash(f"Error: {e}", "danger")

    return render_template_string(TEMPLATE_REGISTER, user=current_user(), alerts=_alerts())


# ══════════════════════════════════════════════════════════════════════════════
# 8. HTML TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
.page{max-width:920px;margin:0 auto;padding:40px 20px}
.card{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;padding:28px;margin-bottom:20px}
h1{font-size:1.5rem;color:#f0f4f8;margin-bottom:6px}
h2{font-size:1rem;color:#718096;font-weight:400;margin-bottom:16px}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:600;letter-spacing:.06em}
.badge-admin{background:#553c9a33;color:#b794f4;border:1px solid #553c9a66}
.badge-user{background:#27674988;color:#68d391;border:1px solid #27674966}
.btn{display:inline-block;padding:10px 20px;border-radius:8px;font-size:.84rem;font-weight:500;
     text-decoration:none;cursor:pointer;border:none;transition:all .2s;font-family:inherit}
.btn-primary{background:#4c51bf;color:#fff}.btn-primary:hover{background:#5a67d8}
.btn-green{background:#22543d;color:#68d391;border:1px solid #276749}.btn-green:hover{background:#276749}
.btn-red{background:#742a2a;color:#fc8181;border:1px solid #9b2c2c}.btn-red:hover{background:#9b2c2c}
.btn-ghost{background:transparent;color:#a0aec0;border:1px solid #2d3748}.btn-ghost:hover{background:#2d3748;color:#f0f4f8}
.nav{display:flex;gap:10px;margin-bottom:28px;flex-wrap:wrap;align-items:center}
.nav-brand{font-weight:700;font-size:1.1rem;color:#f0f4f8;margin-right:6px}
input,select{width:100%;padding:11px 14px;margin-bottom:14px;background:#111827;
             border:1px solid #2d3748;border-radius:8px;color:#e2e8f0;font-size:.9rem;
             outline:none;font-family:inherit}
input:focus,select:focus{border-color:#4c51bf}
label{display:block;font-size:.78rem;color:#a0aec0;margin-bottom:5px}
.alert{padding:11px 16px;border-radius:8px;font-size:.83rem;margin-bottom:14px}
.alert-success{background:#22543d33;color:#68d391;border:1px solid #2f855a55}
.alert-danger{background:#742a2a33;color:#fc8181;border:1px solid #9b2c2c55}
.alert-warning{background:#74421088;color:#f6ad55;border:1px solid #c0562166}
.alert-info{background:#2a436588;color:#63b3ed;border:1px solid #2b6cb066}
table{width:100%;border-collapse:collapse;font-size:.84rem}
th{text-align:left;padding:10px 14px;font-size:.68rem;letter-spacing:.1em;
   text-transform:uppercase;color:#718096;border-bottom:1px solid #2d3748}
td{padding:12px 14px;border-bottom:1px solid #1e2736;color:#cbd5e0}
tr:last-child td{border-bottom:none}
.info-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:16px}
.info-box{background:#111827;border:1px solid #2d3748;border-radius:8px;padding:14px 16px}
.info-lbl{font-size:.63rem;text-transform:uppercase;letter-spacing:.12em;color:#718096;margin-bottom:4px}
.info-val{font-size:1.05rem;font-weight:600;color:#f0f4f8}
.tag{display:inline-block;background:#1e2736;border:1px solid #2d3748;
     border-radius:6px;padding:4px 10px;font-size:.75rem;color:#a0aec0;
     font-family:'Courier New',monospace}
"""

def _alerts():
    from flask import get_flashed_messages
    html = ""
    for cat, msg in get_flashed_messages(with_categories=True):
        html += f'<div class="alert alert-{cat}">{msg}</div>'
    return html


# ── Login ─────────────────────────────────────────────────────────────────────
TEMPLATE_LOGIN = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login</title><style>""" + _CSS + """</style></head>
<body><div class="page" style="max-width:420px">
  <div style="text-align:center;margin-bottom:28px">
    <div style="font-size:2.5rem;margin-bottom:8px">🔐</div>
    <h1 style="font-size:1.5rem">Sign in</h1>
    <p style="color:#718096;font-size:.82rem;margin-top:4px">PostgreSQL · Sessions · RBAC</p>
  </div>
  <div class="card">
    {{ alerts }}
    <form method="POST">
      <label>Username</label>
      <input name="username" placeholder="admin / alice / bob" autofocus autocomplete="username" required>
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" autocomplete="current-password" required>
      <button class="btn btn-primary" style="width:100%;margin-top:4px">Sign in →</button>
    </form>
  </div>
  <div style="background:#1a1f2e;border:1px solid #2d3748;border-radius:10px;
              padding:16px 20px;font-size:.78rem;color:#718096">
    <div style="color:#a0aec0;font-weight:600;margin-bottom:10px">Demo credentials</div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;text-align:center">
      <div><div style="color:#b794f4;font-weight:600">admin</div><div>admin123</div></div>
      <div><div style="color:#68d391;font-weight:600">alice</div><div>alice123</div></div>
      <div><div style="color:#68d391;font-weight:600">bob</div><div>bob123</div></div>
    </div>
  </div>
</div></body></html>"""


# ── Home ──────────────────────────────────────────────────────────────────────
TEMPLATE_HOME = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Home · Flask RBAC</title><style>""" + _CSS + """</style></head>
<body><div class="page">
  <div class="nav">
    <span class="nav-brand">🔐 Flask RBAC</span>
    {% if user %}
      <a href="/dashboard" class="btn btn-ghost">Dashboard</a>
      {% if user.role == 'admin' %}<a href="/admin" class="btn btn-ghost">Admin</a>{% endif %}
      <a href="/logout" class="btn btn-red" style="margin-left:auto">Logout</a>
    {% else %}
      <a href="/login" class="btn btn-primary" style="margin-left:auto">Login</a>
    {% endif %}
  </div>
  <div class="card">
    <h1>Flask + PostgreSQL Auth System</h1>
    <h2>Session-based login · Hashed passwords · Role-Based Access Control</h2>
    <div class="info-row">
      <div class="info-box"><div class="info-lbl">Database</div>
        <div class="info-val" style="font-size:.85rem">PostgreSQL</div></div>
      <div class="info-box"><div class="info-lbl">Driver</div>
        <div class="info-val" style="font-size:.85rem">psycopg2</div></div>
      <div class="info-box"><div class="info-lbl">Hashing</div>
        <div class="info-val" style="font-size:.85rem">Werkzeug</div></div>
      <div class="info-box"><div class="info-lbl">Roles</div>
        <div class="info-val" style="font-size:.85rem">admin · user</div></div>
    </div>
  </div>
  <div class="card">
    <h2 style="margin-bottom:14px">Route protection map</h2>
    <table>
      <thead><tr><th>Route</th><th>Decorator</th><th>Who can access</th></tr></thead>
      <tbody>
        <tr><td><span class="tag">/login</span></td><td>—</td><td>Everyone</td></tr>
        <tr><td><span class="tag">/logout</span></td><td>—</td><td>Everyone</td></tr>
        <tr><td><span class="tag">/dashboard</span></td>
            <td><span class="tag" style="color:#63b3ed">@login_required</span></td>
            <td>Any logged-in user</td></tr>
        <tr><td><span class="tag">/admin</span></td>
            <td><span class="tag" style="color:#b794f4">@admin_required</span></td>
            <td>role = admin only → 403 otherwise</td></tr>
        <tr><td><span class="tag">/register</span></td>
            <td><span class="tag" style="color:#b794f4">@admin_required</span></td>
            <td>Admin creates new accounts</td></tr>
      </tbody>
    </table>
  </div>
</div></body></html>"""


# ── Dashboard ─────────────────────────────────────────────────────────────────
TEMPLATE_DASHBOARD = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard</title><style>""" + _CSS + """</style></head>
<body><div class="page">
  <div class="nav">
    <span class="nav-brand">🔐 Flask RBAC</span>
    <a href="/" class="btn btn-ghost">Home</a>
    {% if user.role == 'admin' %}
      <a href="/admin" class="btn btn-ghost">Admin Panel</a>
      <a href="/register" class="btn btn-green">+ New User</a>
    {% endif %}
    <a href="/logout" class="btn btn-red" style="margin-left:auto">Logout</a>
  </div>
  <div class="card">
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:20px">
      <div style="width:52px;height:52px;border-radius:50%;
                  background:{% if user.role=='admin' %}#44337a{% else %}#22543d{% endif %};
                  display:flex;align-items:center;justify-content:center;
                  font-size:1.4rem;font-weight:700;color:#fff">
        {{ user.username[0]|upper }}
      </div>
      <div>
        <h1>{{ user.username }}</h1>
        <span class="badge badge-{{ user.role }}">{{ user.role }}</span>
      </div>
    </div>
    <div class="info-row">
      <div class="info-box">
        <div class="info-lbl">User ID (DB)</div>
        <div class="info-val">#{{ user.id }}</div>
      </div>
      <div class="info-box">
        <div class="info-lbl">Username</div>
        <div class="info-val">{{ user.username }}</div>
      </div>
      <div class="info-box">
        <div class="info-lbl">Role</div>
        <div class="info-val"
             style="color:{% if user.role=='admin' %}#b794f4{% else %}#68d391{% endif %}">
          {{ user.role }}
        </div>
      </div>
      <div class="info-box">
        <div class="info-lbl">Session</div>
        <div class="info-val" style="color:#68d391;font-size:.85rem">✓ Active</div>
      </div>
    </div>
  </div>
  {% if user.role == 'user' %}
  <div class="card" style="border-color:#2b6cb044;background:#0f1e30">
    <div style="color:#63b3ed;font-size:.78rem;margin-bottom:6px">ℹ Role restriction active</div>
    <div style="color:#a0aec0;font-size:.84rem;line-height:1.6">
      You are a <strong>regular user</strong>. Visiting
      <span class="tag">/admin</span> returns
      <strong style="color:#fc8181">HTTP 403 Forbidden</strong> — enforced by
      <span class="tag" style="color:#b794f4">@admin_required</span>.
    </div>
  </div>
  {% endif %}
</div></body></html>"""


# ── Admin ─────────────────────────────────────────────────────────────────────
TEMPLATE_ADMIN = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel</title><style>""" + _CSS + """</style></head>
<body><div class="page">
  <div class="nav">
    <span class="nav-brand">🔐 Flask RBAC</span>
    <a href="/dashboard" class="btn btn-ghost">Dashboard</a>
    <a href="/register" class="btn btn-green">+ New User</a>
    <a href="/logout" class="btn btn-red" style="margin-left:auto">Logout</a>
  </div>
  <div class="card" style="border-color:#553c9a55">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <span style="font-size:2rem">⚙️</span>
      <div>
        <h1>Admin Panel</h1>
        <h2>Protected by <span class="tag" style="color:#b794f4">@admin_required</span>
            — returns 403 for non-admins</h2>
      </div>
    </div>
    <div class="info-row">
      <div class="info-box" style="border-color:#553c9a55">
        <div class="info-lbl">Logged in as</div>
        <div class="info-val">{{ user.username }}</div>
      </div>
      <div class="info-box" style="border-color:#553c9a55">
        <div class="info-lbl">Role verified</div>
        <div class="info-val" style="color:#b794f4">admin ✓</div>
      </div>
      <div class="info-box" style="border-color:#553c9a55">
        <div class="info-lbl">Total users (DB)</div>
        <div class="info-val">{{ all_users|length }}</div>
      </div>
    </div>
  </div>
  <div class="card">
    <h2 style="margin-bottom:16px">Users table — PostgreSQL</h2>
    <table>
      <thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th></tr></thead>
      <tbody>
        {% for u in all_users %}
        <tr>
          <td style="color:#718096">#{{ u.id }}</td>
          <td style="color:#f0f4f8;font-weight:500">{{ u.username }}</td>
          <td><span class="badge badge-{{ u.role }}">{{ u.role }}</span></td>
          <td style="color:#718096;font-size:.78rem">
            {{ u.created_at.strftime('%Y-%m-%d %H:%M') if u.created_at else '—' }}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div></body></html>"""


# ── Register ──────────────────────────────────────────────────────────────────
TEMPLATE_REGISTER = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>New User</title><style>""" + _CSS + """</style></head>
<body><div class="page" style="max-width:460px">
  <div class="nav">
    <span class="nav-brand">🔐 Flask RBAC</span>
    <a href="/admin" class="btn btn-ghost" style="margin-left:auto">← Back</a>
  </div>
  <div class="card">
    <h1>Create account</h1>
    <h2>Admin-only · saved to PostgreSQL</h2>
    {{ alerts }}
    <form method="POST">
      <label>Username</label>
      <input name="username" placeholder="e.g. carol" required autocomplete="off">
      <label>Password</label>
      <input type="password" name="password" placeholder="min 8 chars" required>
      <label>Role</label>
      <select name="role">
        <option value="user">user</option>
        <option value="admin">admin</option>
      </select>
      <button class="btn btn-green" style="width:100%;margin-top:4px">Create user →</button>
    </form>
  </div>
</div></body></html>"""


# ── 403 Forbidden ─────────────────────────────────────────────────────────────
TEMPLATE_403 = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403 Forbidden</title><style>""" + _CSS + """</style></head>
<body><div class="page" style="max-width:480px;text-align:center;padding-top:80px">
  <div style="font-size:4rem;margin-bottom:14px">🚫</div>
  <h1 style="font-size:3.5rem;color:#fc8181;margin-bottom:6px">403</h1>
  <h2 style="color:#a0aec0;font-weight:400;margin-bottom:20px">Access Forbidden</h2>
  <p style="color:#718096;font-size:.85rem;line-height:1.7;margin-bottom:28px">
    This page requires <strong style="color:#b794f4">admin</strong> privileges.<br>
    Your session role (<strong style="color:#68d391">user</strong>) does not have permission.<br>
    This is enforced by <span class="tag" style="color:#b794f4">@admin_required</span>.
  </p>
  <div style="display:flex;gap:10px;justify-content:center">
    <a href="/dashboard" class="btn btn-ghost">← Dashboard</a>
    <a href="/logout" class="btn btn-red">Logout</a>
  </div>
</div></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# 9. STARTUP
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        init_db()
    except Exception as e:
        print(f"\n  [ERROR] Could not connect to PostgreSQL: {e}")
        print("  Make sure DATABASE_URL is set in your .env file.\n")
        raise SystemExit(1)

    print("\n  Flask RBAC + PostgreSQL running")
    print("  →  http://127.0.0.1:5000")
    print("  Accounts: admin/admin123  |  alice/alice123  |  bob/bob123\n")
    app.run(debug=True, port=5000)
