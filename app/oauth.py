import os

from flask_login import login_user, current_user

from flask_dance.consumer import oauth_authorized
from flask_dance.contrib.github import make_github_blueprint
from flask_dance.contrib.twitter import make_twitter_blueprint
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage

from sqlalchemy.orm.exc import NoResultFound

from app.config import providers
from app.models import OAuth, User, db


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

twitter_blueprint = make_twitter_blueprint(
    api_key=os.getenv("TWITTER_KEY"),
    api_secret=os.getenv("TWITTER_SECRET"),
    storage=SQLAlchemyStorage(
        OAuth,
        db.session,
        user=current_user,
        user_required=False,
    ),
)

# signal to manage/create user when login
@oauth_authorized.connect_via(github_blueprint)
@oauth_authorized.connect_via(twitter_blueprint)
def provider_logged_in(blueprint, token):

    provider = blueprint.name
    app = providers[provider]["app"]
    url = providers[provider]["url"]
    key = providers[provider]["user_key"]

    info = app.get(url)
    if info.ok:
        account_info = info.json()
        username = account_info[key]

        query = User.query.filter_by(username=username)
        try:
            user = query.one()
        except NoResultFound:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        login_user(user)