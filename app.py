from flask import Flask, render_template, request, redirect, url_for, session
from markupsafe import escape
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"


# ---------------- DATABASE ----------------

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    # Users table
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    from werkzeug.security import generate_password_hash
    # Create default admin if not exists
    admin_email = "admin@faith.com"
    admin_password = generate_password_hash("admin123")
    existing_admin = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (admin_email,)
        ).fetchone()
    if not existing_admin:
        conn.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
            (admin_email, admin_password, "admin")
            )
        conn.commit()

    # Messages table
    conn.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        text TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

    conn = get_db_connection()
    columns = conn.execute("PRAGMA table_info(users)").fetchall()
    column_names = [column[1] for column in columns]
    if "role" not in column_names:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'intern'")
        conn.commit()
        conn.close()

# Initialize database ONCE at startup
init_db()


# ---------------- ROUTES ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                (email, password, 'intern')
                )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "User already exists"
        conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = email
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        return "Invalid credentials"

    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    if request.method == "POST":
        msg = escape(request.form["message"])
        conn.execute(
            "INSERT INTO messages (user, text) VALUES (?, ?)",
            (session["user"], msg)
        )
        conn.commit()

    messages = conn.execute(
        "SELECT user, text FROM messages ORDER BY id ASC"
    ).fetchall()

    conn.close()

    return render_template("dashboard.html", messages=messages)

@app.route("/hr")
def hr_portal():
    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access Denied - Admin Only"

    return render_template("hr.html")

@app.route("/announcements")
def announcements():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("announcements.html")


@app.route("/resources")
def resources():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("resources.html")


@app.route("/security")
def security():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("security.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
