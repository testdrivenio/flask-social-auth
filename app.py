from flask import Flask, redirect, url_for, render_template

from flask_dance.contrib.github import github
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin, SQLAlchemyStorage
from flask_dance.consumer import oauth_authorized

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound

from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    logout_user,
    login_user,
    login_required,
)

from blueprints.github import github_blueprint

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./users.db"
app.register_blueprint(github_blueprint, url_prefix="/login")

db = SQLAlchemy(app)
login_manager = LoginManager(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True)


class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


github_blueprint.storage = SQLAlchemyStorage(
    OAuth,
    db.session,
    user=current_user,
    user_required=False,
)


@app.route("/")
def homepage():
    return render_template("index.html")


@app.route("/github")
def login():
    if not github.authorized:
        return redirect(url_for("github.login"))
    res = github.get("/user")
    username = res.json()["login"]
    return f"You are @{username} on GitHub"


# signal to manage/create user when login
@oauth_authorized.connect_via(github_blueprint)
def github_logged_in(blueprint, token):
    info = github.get("/user")
    if info.ok:
        account_info = info.json()
        username = account_info["login"]

        query = User.query.filter_by(username=username)
        try:
            user = query.one()
        except NoResultFound:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        login_user(user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("homepage"))


if __name__ == "__main__":
    app.run(debug=True)