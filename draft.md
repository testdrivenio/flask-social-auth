# Adding Social Authentication to Flask

In this tutorial, we'll look at how to add social auth, with GitHub and Twitter, to a Flask application.

> Social login (also known as social login or social signon) is a process of authenticating a user based on a third-party service, without relying on your own authentication service. For example, the `Sign in with Google` button that you see on a website is the best example of social login. Here google authenticates the user and provides a token to the application for managing the user's session.

Using a social auth has its advantages. You won't need to set up auth for the web application, since it's handled by the third-party, [OAuth provider](https://en.wikipedia.org/wiki/List_of_OAuth_providers). Also, since providers like Google, Facebook, and GitHub perform extensive checks to prevent unauthorized access to their services, leveraging social auth instead of rolling your own auth mechanism can boost your application's security.

Along with Flask, we'll use [Flask-Dance](https://flask-dance.readthedocs.io/en/latest/) to enable social auth,[Flask-Login](https://flask-login.readthedocs.io/) for logging users in and out and managing sessions, and [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/) for interacting with a database to store user-related data.

### Why Use Social Authentication?

Why would you want to leverage social auth over rolling your own auth?

#### Pros

- No need to spin up your own authentication workflow
- Improved security. Third-party auth providers like Google, Facebook, etc., focus heavily on security. Using such services can improve the security of your own application.
- You can automatically retrieve the username, email, and other data from the authentication provider. This improves the signup experience by eliminating this step (manually asking them).

#### Cons

- Your application now depends on another application outside your control. If the third-party application goes down, users won't be able to sign up or log in.
- People tend to ignore the permissions requested by an authentication provider. Some applications might even access data that's not required.
- Social login cannot be the sole authentication method, as the users with no social account might need to create one to log in. The best approach is to provide both(social + your own) and let the user choose.
1. Users that don't have accounts on one of the providers that you have configured won't be able to access your application. The best approach is to implement both -- e.g., username and password and social auth -- and let the user choose.

## OAuth

Social auth is most often implemented with [OAuth](https://oauth.net/) -- an open standard protocol for authorization -- where a third-party auth provider verifies a user's identity.

The most common flow (or grant) is [authorization code](https://oauth.net/2/grant-types/authorization-code/):

1. A user attempts to log in to your app using their account from a third-party auth provider
1. They are redirected to the auth provider for verification
1. After verification, they are then redirected back to your app with an authorization code
1. You then need to make a request, to the auth provider, with the authorization code for an access token
1. After the provider verifies authorization code, they send back the access token
1. The user is then logged in so they can access the protected resources
1. The access token can then be used to get data from the auth provider

![flow](images/flow.png)

> For more on OAuth, review [An Introduction to OAuth 2](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2).

Let's look at a quick example of this flow using GitHub:

```python
"""
Import necessary modules.
  - `os` to read env variable
  - `requests` to make GET/POST requests
  - `parse_qs` to parse the response
"""
import os
import requests
from urllib.parse import parse_qs


"""
Define the GITHUB_ID and GITHUB_SECRET environment variables
along with the endpoints.
"""
CLIENT_ID = os.getenv("GITHUB_ID")
CLIENT_SECRET = os.getenv("GITHUB_SECRET")
AUTHORIZATION_ENDPOINT = f"https://github.com/login/oauth/authorize?response_type=code&client_id={os.getenv('GITHUB_ID')}"
TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
USER_ENDPOINT = "https://api.github.com/user"


"""
1. Log in via the browser using the 'Authorization URL' outputted in the terminal.
   (If you're already logged in to GitHub, either log out or test in an incognito/private browser window.)
2. Once logged in, the page will redirect. Grab the code from the redirect URL.
3. Paste the code in the terminal.
"""
print(f"Authorization URL: {AUTHORIZATION_ENDPOINT}")
code = input("Enter the code: ")


"""
Using the authorization code, we can request an access token.
"""
# Once we get the code, we sent the code to the access token
# endpoint(along with id and secret). The response contains
# the access_token and we parse is using parse_qs
res = requests.post(
    TOKEN_ENDPOINT,
    data=dict(
        client_id=os.getenv("GITHUB_ID"),
        client_secret=os.getenv("GITHUB_SECRET"),
        code=code,
    ),
)
res = parse_qs(res.content.decode("utf-8"))
token = res["access_token"][0]


"""
Finally, we can use the access token to obtain information about the user.
"""
user_data = requests.get(USER_ENDPOINT, headers=dict(Authorization=f"token {token}"))
username = user_data.json()["login"]
print(f"You are {username} on GitHub")
```

To test, save this code to a file called *oath.py*. Make sure to review the comments.

Follow these steps to obtain new OAuth app ID and Secret from GitHub.

1. Log in to your GitHub account, and then navigate to [https://github.com/settings/applications/new](https://github.com/settings/applications/new) to create a new [OAuth application](https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps):

![Register GitHub application](images/github_register.PNG)

```text
Application name: Testing Flask-Dance
Homepage URL: http://127.0.0.1:5000
Callback URL: http://127.0.0.1:5000/login/github/authorized
```

Once the app is created, you'll get ID and SECRET.

![GitHub ID and Secret](images/github_tokens.PNG)

Set the values to environment variables by running the following from a terminal.


```bash
export GITHUB_ID=<your-github-id>
export GITHUB_SECRET=<your-github-secret>
# for windows machine, use `set` instead of `export`
```

Install the [requests](https://requests.readthedocs.io/en/master/) library. Then, run `python oauth.py`.

![demo](images/terminal.gif)

## Flask Extensions

- [OAuthLib](https://github.com/oauthlib/oauthlib)
- [Requests-OAuthlib](https://github.com/requests/requests-oauthlib)
- [Python Social Auth - Flask](https://github.com/python-social-auth/social-app-flask)
- [Flask-Social](https://github.com/mattupstate/flask-social/)
- [Flask-Social-Blueprint](https://github.com/wooyek/flask-social-blueprint)

For this tutorial, we will be using [Flask-Dance](https://flask-dance.readthedocs.io/en/latest/). Flask-Dance is a library built on top of OAuthLib designed specifically for Flask. It has a simple API that lets you quickly add social login to a Flask app. It is also the most popular among OAuth libraries designed for Flask. 

## GitHub Provider

We have already seen how to generate GitHub ID and SECRET. Copy the generated tokens and save them to a `.env` file(flask will automatically load `.env` file).

```env
GITHUB_ID=<YOUR_ID_HERE>
GITHUB_SECRET=<YOUR_SECRET_HERE>

OAUTHLIB_INSECURE_TRANSPORT=1
```

`OAUTHLIB_INSECURE_TRANSPORT=1` is required for testing purposes as OAuthLib defaults to requiring HTTPS.

Install the required dependencies:

```bash
pip install flask Flask==1.1.2 Flask-Dance==3.2.0 python-dotenv==0.15.0
```

Flask-Dance provides Flask [blueprints](https://flask-dance.readthedocs.io/en/latest/concepts.html#blueprints) for each provider. Let's create one for the GitHub provider in *app/oauth.py*:

```python
# app/oauth.py

import os
from flask_dance.contrib.github import make_github_blueprint

github_blueprint = make_github_blueprint(
    client_id=os.getenv("GITHUB_ID"),
    client_secret=os.getenv("GITHUB_SECRET"),
)
```

Now let's create a new Flask app and add the GitHub blueprint to it:

```python
# main.py

from flask import Flask, redirect, url_for
from flask_dance.contrib.github import github

from app.oauth import github_blueprint

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.register_blueprint(github_blueprint, url_prefix="/login")


@app.route("/")
def login():
    if not github.authorized:
        return redirect(url_for("github.login"))
    res = github.get("/user")

    return f"You are @{res.json()['login']} on GitHub"


if __name__ == "__main__":
    app.run(debug=True)
```

The route `/` redirects to the `github authentication` page, if the user is not already logged in. Once logged in, it displays the username.

Start the application by running `python main.py`, navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000) and test the app:

![Demo 1](images/github-flask-dance.gif)

## Twitter Provider

Setting up the Twitter provider is similar to GitHub:

1. Create an OAuth app on Twitter
1. Configure the Twitter blueprint
1. Set up a route to redirect to Twitter login

Start by [applying](https://developer.twitter.com/en/portal/dashboard) for a Twitter developer account (if you don't already have one). Once created, navigate to [Projects and Apps](https://developer.twitter.com/en/portal/projects-and-apps) and click "Create App".

Give the app a name, and take note of the API key and API secret key. Then, under "Authentication Settings". Enable "Enable 3-legged OAuth" and "Request email address from users". Add the Callback, Website, Terms of service, and Privacy policy URLs as well:

```text
Callback URL: http://127.0.0.1:5000/login/twitter/authorized
Website URL: http://example.com
Terms of service: http://example.com
Privacy policy: http://example.com
```

![twitter settings](images/twitter_settigs.PNG)

![twitter callback](images/twitter_callback.PNG)

Add the tokens to our `.env` file.

![twitter tokens](images/twitter_tokens.PNG)

```env
TWITTER_API_KEY=<your-twitter-api-key>
TWITTER_API_SECRET=<your-twitter-api-secret>
```

Now create a Twitter blueprint in *oauth.py*:

```python
from flask_dance.contrib.twitter import make_twitter_blueprint

twitter_blueprint = make_twitter_blueprint(
    api_key=os.getenv("TWITTER_API_KEY"),
    api_secret=os.getenv("TWITTER_API_SECRET"),
)
```

Remember: Currently we're creating a Twitter app independent of the GitHub application. We'll see how to add both Twitter and GitHub login and use Flask-Login to manage users in later sections.

Now we set up the route to authenticate via twitter:

```python
# main.py

from flask import Flask, redirect, url_for
from flask_dance.contrib.twitter import twitter

from app.oauth import twitter_blueprint

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.register_blueprint(twitter_blueprint, url_prefix="/login")


@app.route("/")
def login():
    if not twitter.authorized:
        return redirect(url_for("twitter.login"))
    res = twitter.get("account/settings.json")

    return f"You are @{res.json()['screen_name']} on Twitter"


if __name__ == "__main__":
    app.run(debug=True)
```

This works the same as the GitHub authentication: It checks if the user has already authenticated. If not, it redirects the user to the Twitter auth page. The only differences between GitHub and Twitter authentication are the endpoint to fetch user data and the key to get the username from the fetched data:

|                             | GitHub | Twitter                |
|-----------------------------|--------|------------------------|
| Endpoint to fetch user data | /user  | /account/settings.json |
| Key for username            | login  | screen_name            |

We've now finished setting up social authentication with GitHub and Twitter.

## Login Flow

Next, let's wire up [Flask-Login](https://flask-login.readthedocs.io/) for managing user sessions along with [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/) for storing user-related data.

### Setup

Project Structure:

```bash
├── app
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   └── oauth.py
├── main.py
├── requirements.txt
├── templates
│   ├── _base.html
│   └── index.html
└── users.db
```

Start by installing the required dependencies:

```bash
pip install Flask-Login==0.5.0 Flask-SQLAlchemy==2.4.4
```

Create the models to store user and OAuth info:

```python
# app/models.py

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True)


class OAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)


login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
```

This will create two tables, `user` and `flask_dance_oauth`:

```bash
# user table

name          type
--------  ------------
id        INTEGER
username  VARCHAR(250)

# flask_dance_oauth table

name        type
----------  -----------
id          INTEGER
provider    VARCHAR(50)
created_at  DATETIME
token       TEXT
user_id     INTEGER
```

> `OAuthConsumerMixin` will automatically add the necessary fields to store OAuth information. The login manager will fetch users from the `user` table.

TODO:

### GitHub Blueprint

Now we modify the GitHub blueprint created earlier to add the `OAuth` table as storage:

```python
# app/oauth.py

import os
from flask_login import current_user
from flask_dance.contrib.github import make_github_blueprint
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
```

Here, we passed in:

1. `storage` as SQLAlchemy [storage](https://flask-dance.readthedocs.io/en/latest/storages.html) with the `OAuth` model
1. `db.session`, which is a `sqlalchemy.session`
1. The user as `current_user` from Flask Login.

### Endpoints

Next, let's define the appropriate endpoints -- `login`, `logout`, and `homepage`:

```python
# main.py

from flask import Flask, redirect, url_for, render_template

from flask_login import logout_user, login_required

from app.models import db, login_manager
from app.oauth import github_blueprint

...

app = Flask(__name__)

...

db.init_app(app)
login_manager.init_app(app)

with app.app_context():
    db.create_all()

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

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("homepage"))
```

Here, we initialized the `db` and `login_manager` defined earlier in *models.py*.

The `homepage` view renders the *index.html* template, which we'll add shortly. Next, the `login` view authenticates with GitHub and returns the username. The `logout` route logs the user out.

All the routes are now setup, but we haven't logged the user in yet. For that, we'll use Flask [Signals](https://flask.palletsprojects.com/en/1.1.x/signals/).

### Signals

Signals allow you to perform actions when certain predefined events occur. In our case, we'll log the user in when the GitHub authentication is successful.

Signals requires [Binker](https://pypi.org/project/blinker/) to work, so go ahead and install it now:

```sh
$ pip install blinker==1.4
```

Add a new helper to *app/oauth.py*:

```python
# app/oauth.py

from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound


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
```

When the user connects via the `github_blueprint`, the `github_logged_in` function gets executed. It takes in two parameters: the blueprint and the token (from GitHub). We grabbed the username from the provider and performed one of two actions:

1. If the username is already present in the tables, we log the user in
1. If not, we create a new user and then log the user in

## Templates

Finally, let's add the templates:

```bash
mkdir templates && cd templates
touch _base.html
touch index.html
```

The *_base.html* templates contains the general layout:

```html
<!-- templates/_base.html -->

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
    <link
      rel="stylesheet"
      href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Flask Social Login</title>
  </head>
  <body style="padding-top: 10%;">
    {% block content %} {% endblock content %}
  </body>
</html>
```

Next, add a "Login with GitHub" button to *index.html*:

```html
<!-- templates/index.html -->

{% extends '_base.html' %}

{% block content %}
    <center>
        {% if current_user.is_authenticated %}
            <h1>You are logged in as {{current_user.username}}</h1>
            <br><br>
            <a href="{{url_for('logout')}}" class="btn btn-danger">Logout</a>
        {% else %}
            <!-- GitHub button starts here -->
            <a href="{{url_for('login')}}"  class="btn btn-secondary">
                <i class="fa fa-github fa-fw"></i>
                <span>Login with GitHub</span>
            </a>
            <!-- GitHub button ends here -->
        {% endif %}
    </center>
{% endblock content %}
```

Once done, start the app and navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000). Test out the auth flow:

![demo 2](images/github-login.gif)

## Twitter Login Flow

The GitHub + Flask-Login should give you a fare idea on how the Twitter login should be setup. We follow the same steps as we did got GitHub.

1. Create a new blueprint for Twitter(we have already seen this)
1. Create a new endpoint for twitter login
    - @app.route("/twitter")
1. Create a new flask signal to login user when they authorize via twitter 
    - @oauth_authorized.connect_via(twitter_blueprint)

Once these steps are completed, your twitter login should be done. However, we have created an endpoint and a signal for each provider. This is not good when setting up more providers. Instead of repeating the code, we wire up GitHub and Twitter to use same endpoint and signal for login. You can read about the [endpoint](https://github.com/testdrivenio/flask-social-auth/blob/fa21a48d6554e7cdb70316987872b4b38e993bba/main.py#L27) and the [signal](https://github.com/testdrivenio/flask-social-auth/blob/fa21a48d6554e7cdb70316987872b4b38e993bba/app/oauth.py#L39) in the [repo](https://github.com/testdrivenio/flask-social-auth) for this tutorial. 
## Conclusion

This tutorial detailed how to add social auth to a Flask app using Flask-Dance. After configuring both GitHub and Twitter, you should now have a solid understanding of how to wire up new social auth providers:

1. Grab the tokens for each provider by creating OAuth applications.
1. Setup database models to store user as well as oauth data.
1. Create blueprints for each provider and add the created oauth model as storage.
1. Add a route to authenticate with the provider.
1. Add a signal to login the user when authenticated.

Looking for additional challenges?

1. Figure out how to link multiple social media logins to a single account (so if a user logs in with a different social media account, rather than creating a new row in the `user` table, the new social media account is linked to the existing user.).
1. Get additional info from the social provider about the user (i.e., email, language, country) by specifying OAuth scopes.

Grab the code from [flask-social-auth](https://github.com/testdrivenio/flask-social-auth) repository on GitHub.
