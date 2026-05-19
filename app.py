"""Веб-интерфейс статистики Apache access log."""

from __future__ import annotations

from functools import wraps

from flask import Flask, redirect, render_template, request, session, url_for

from database import db_session, get_stats, get_user, init_db, load_config, verify_password
from log_parser import import_logs as run_import

cfg = load_config()
server_cfg = cfg.get("server", {})

app = Flask(__name__)
app.secret_key = server_cfg.get("secret_key", "dev-secret-key")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db_session() as conn:
            user = get_user(conn, username)
        if user and verify_password(password, user["password_hash"]):
            session["user"] = username
            return redirect(url_for("index"))
        error = "Неверный логин или пароль"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    with db_session() as conn:
        stats = get_stats(conn)
    flash = session.pop("flash", None)
    return render_template("index.html", stats=stats, flash=flash)


@app.route("/import", methods=["POST"])
@login_required
def import_logs():
    with db_session() as conn:
        result = run_import(conn)
    session["flash"] = (
        f"Импорт: +{result['imported']} строк, пропущено {result['skipped']}. {result['message']}"
    )
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    host = server_cfg.get("host", "127.0.0.1")
    port = int(server_cfg.get("port", 5000))
    print(f"http://{host}:{port}  (логин: {cfg['auth']['username']} / {cfg['auth']['password']})")
    app.run(host=host, port=port, debug=True)
