from flask import Flask, redirect, url_for, render_template

from flask_login import logout_user, login_required

from app.config import providers
from app.models import db, login_manager
from app.oauth import github_blueprint, twitter_blueprint, provider_logged_in

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./users.db"
app.register_blueprint(github_blueprint, url_prefix="/login")
app.register_blueprint(twitter_blueprint, url_prefix="/login")

db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    db.create_all()


@app.route("/")
def homepage():
    return render_template("index.html")


@app.route("/accounts/<provider>")
def login(provider: str):

    app = providers[provider]["app"]
    url = providers[provider]["url"]
    key = providers[provider]["user_key"]

    if not app.authorized:
        return redirect(url_for(f"{provider}.login"))
    res = app.get(url)
    username = res.json()[key]
    return f"You are @{username} on {provider.capitalize()}"


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("homepage"))


if __name__ == "__main__":
    app.run(debug=True)