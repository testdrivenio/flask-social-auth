import os
from flask_login import current_user
from flask_dance.contrib.github import make_github_blueprint
from flask_dance.contrib.twitter import make_twitter_blueprint
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage

from app.models import OAuth, db

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