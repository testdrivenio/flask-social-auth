# app/oauth.py

import os

from flask_login import current_user, login_user
from flask_dance.consumer import oauth_authorized
from flask_dance.contrib.github import github, make_github_blueprint
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_dance.contrib.google import google, make_google_blueprint
from sqlalchemy.orm.exc import NoResultFound

from app.models import db, OAuth, User


github_blueprint = make_github_blueprint(
    client_id=os.getenv("GITHUB_ID"),
    client_secret=os.getenv("GITHUB_SECRET"),
    storage=SQLAlchemyStorage(
        OAuth,
        db.session,
        user=current_user,
        user_required=False,
    ),
)

google_blueprint = make_google_blueprint(
    client_id=os.getenv("GOOGLE_ID"),
    client_secret=os.getenv("GOOGLE_SECRET"),
    scope=["profile", "email"],
    storage=SQLAlchemyStorage(
        OAuth,
        db.session,
        user=current_user,
        user_required=False,
    ),
)


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


@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    info = google.get("/oauth2/v2/userinfo")
    if info.ok:
        account_info = info.json()
        username = account_info["email"]
        query = User.query.filter_by(username=username)
        try:
            user = query.one()
        except NoResultFound:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        login_user(user)
