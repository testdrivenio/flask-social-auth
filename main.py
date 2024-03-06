# main.py

from flask import Flask, jsonify, redirect, render_template, url_for
from flask_dance.contrib.github import github
from flask_dance.contrib.google import google
from flask_login import logout_user, login_required
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError

from app.models import db, login_manager
from app.oauth import github_blueprint, google_blueprint


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./users.db"
app.secret_key = "supersecretkey"
app.register_blueprint(github_blueprint, url_prefix="/login")
app.register_blueprint(google_blueprint, url_prefix="/login")

db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    db.create_all()


@app.route("/ping")
def ping():
    return jsonify(ping="pong")


@app.route("/")
def homepage():
    return render_template("index.html")


@app.route("/github")
def login_github():
    if not github.authorized:
        return redirect(url_for("github.login"))
    res = github.get("/user")
    username = res.json()["login"]
    return f"You are @{username} on GitHub"


@app.route("/google")
def login_google():
    try:
        if not google.authorized:
            return redirect(url_for("google.login"))
        res = google.get("/oauth2/v2/userinfo")
        username = res.json()["email"]
        return f"You are @{username} on Google"
    except TokenExpiredError as e:
        return redirect(url_for("google.login"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("homepage"))


if __name__ == "__main__":
    app.run(debug=True)
