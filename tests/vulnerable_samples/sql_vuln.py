
import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/search")
def search_users():
    """
    Intentionally vulnerable SQL patterns:
    - f-string with raw user input
    - string concatenation
    - %-formatting
    """
    username = request.args.get("username", "")
    city = request.args.get("city", "")

    conn = get_db()
    cur = conn.cursor()

    # 1) f-string SQL injection
    query1 = f"SELECT * FROM users WHERE username = '{username}'"
    cur.execute(query1)  # nosec

    # 2) string concatenation SQL injection
    query2 = "SELECT * FROM users WHERE city = '" + city + "'"
    cur.execute(query2)  # nosec

    # 3) %-formatting SQL injection
    query3 = "SELECT * FROM users WHERE username = '%s' AND city = '%s'" % (
        username,
        city,
    )
    cur.execute(query3)  # nosec

    return {"status": "ok"}


def safe_example():
    """Non-vulnerable prepared statement for contrast (should not be flagged)."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (1,))
    return cur.fetchall()

