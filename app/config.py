from flask_dance.contrib.github import github
from flask_dance.contrib.twitter import twitter

providers = {
    "github": {
        "app": github,
        "url": "/user",
        "user_key": "login",
    },
    "twitter": {
        "app": twitter,
        "url": "account/settings.json",
        "user_key": "screen_name",
    },
}