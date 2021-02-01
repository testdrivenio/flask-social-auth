In this tutorial, we'll see how to implement social authentication for a flask application. 

Social authentication is a process of authenticating a user based on a third-party service, without relying on your own authentication service. For example, the `Sign in with Google` button that you see on a website is the best example of social login. Here google authenticates the user and provides a token to the application to manage the user(session). 

### Why use Social authentication?

Like every other system, social authentication has its pros and cons. 

#### Pros

- No need to spin up your own authentication workflow
- Third-party auth providers like Google, Facebook, etc., have a high priority for their application security. Using these services can significantly improve the security of our application.
- You can automatically retrieve the username, email, and other data from the authentication provider. This improves the signup experience by eliminating one step(manually asking them).

#### Cons

- Your application now depends on another application that is outside your control. If the third-party application goes down, so does your authentication.
- People tend to ignore the permissions requested by an authentication provider. Some applications might even access data that is more than required.
- Social login cannot be the sole authentication method, as the users with no social account might need to create one to log in. The best approach is to provide both(social + your own) and let the user choose.

### How does OAuth work?

![flow](images/flow.png)

- The user logs into the provider account.
- The provider verifies the credentials, and send back and authorization code.
- The user requests for an access token using the code
- The provider verifies the code and provides a new access token
- The user requests data using the access token
- The provider verifies the access token and sends back requested data


Let's see github authentication using simple python requests,

```python
# import necessary modules. `os` to read env variable, `requests` 
# to make GET/POST requests, and `parse_qs` to parse the response
# it stands for parse_querystring.

import os
import requests
from urllib.parse import parse_qs


# define all the endpoints. Here we have the GITHUB_ID, GITHUB_SECRET 
# set in environment variables

AUTHORIZATION_ENDPOINT = f"https://github.com/login/oauth/authorize?response_type=code&client_id={os.getenv('GITHUB_ID')}"
TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
USER_ENDPOINT = "https://api.github.com/user"

# First we login via browser, using the URL on terminal.
# Once logged in, the page redirects. Here we to provide 
# the `code` in the redirect URL. Copy and paste the code
# in the terminal 

print(f"Authorization URL: {AUTHORIZATION_ENDPOINT}")
code = input("Enter the code: ")

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

# Now that we have access_token, we send it back to 
# the user data endpoint and display the username from 
# response

user_data = requests.get(USER_ENDPOINT, headers=dict(Authorization=f"token {token}"))
username = user_data.json()["login"]
print(f"You are {username} on GitHub")
```

Test it yourself by running `python oauth.py`

#### Demo

![demo](images/terminal.gif)

### GitHub example with Flask-dance

[Flask-dance](https://flask-dance.readthedocs.io/en/latest/) is a library built on top of oauthlib for Flask. It has a simple API that lets you build social login for your application. 

First, we need to get GitHub OAuth tokens by creating a new OAuth application. Navigate to [https://github.com/settings/applications/new](https://github.com/settings/applications/new) to create a new [OAuth application](https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps)

![Register GitHub application](images/github_register.PNG)

> Application Name: flask-dance tutorial
> Homepage URL: http://127.0.0.1:5000
> Callback URL: http://127.0.0.1:5000/login/github/authorized

![GitHub ID and Secret](images/github_tokens.PNG)

Copy the generated tokens and save them to a `.env` file

```env
GITHUB_ID=<YOUR_ID_HERE>
GITHUB_SECRET=<YOUR_SECRET_HERE>

OAUTHLIB_INSECURE_TRANSPORT=1
```

`OAUTHLIB_INSECURE_TRANSPORT=1` is required as oauthlib works only over HTTPS. This helps us test the app locally.

Install the required dependencies

```bash
pip install flask Flask==1.1.2 Flask-Dance==3.2.0 python-dotenv==0.15.0
```

Flask-dance provides blueprints for each provider. Let's create one for GitHub provider in `app/oauth.py`.

```python
# app/oauth.py

import os
from flask_dance.contrib.github import make_github_blueprint

github_blueprint = make_github_blueprint(
    client_id=os.getenv("GITHUB_ID"),
    client_secret=os.getenv("GITHUB_SECRET"),
)
```

Now let's create a new flask app and add the github blueprint to it.

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

The route `/` redirects to the `github authentication` page(if not logged in). Once logged in, it displays the username.

Start the application by running `python main.py`, navigate to http://127.0.0.1:5000 and test the app.

#### Demo

![Demo 1](images/github-flask-dance.gif)


### Twitter login with Flask-dance

The Twitter login is similar to github login. We do the following tasks,

- Obtain Twitter OAuth tokens by creating a new OAuth application
- Create a Twitter blueprint
- Set up a route to redirect to Twitter login

Create a new Twitter OAuth application [here](https://developer.twitter.com/en/portal/apps/new). After creating a new app, go to the app settings and `edit` the authentication settings.

![twitter settings](images/twitter_settigs.PNG)

Turn on the `3-legged OAuth` and set the following.

> Callback URL: http://127.0.0.1:5000/login/twitter/authorized
> Website URL: http://localhost.com (or any valid URL)

![twitter callback](images/twitter_callback.PNG)

Navigate to the `keys and tokens` tab on top and Create a new API key and secret. Add the tokens to our `.env` file.

![twitter tokens](images/twitter_tokens.PNG)

```env
TWITTER_API_KEY=<your-twitter-api-key>
TWITTER_API_SECRET=<your-twitter-api-secret>
```

Now create a Twitter blueprint in `oauth.py`,

```python
from flask_dance.contrib.twitter import make_twitter_blueprint

twitter_blueprint = make_twitter_blueprint(
    api_key=os.getenv("TWITTER_API_KEY"),
    api_secret=os.getenv("TWITTER_API_SECRET"),
)
```

Remember, currently we are creating a Twitter app independent of the github application. We'll see how to add both Twitter and github login and use flask-login to manage users in later sections.

Now we set up the route to authenticate via twitter,

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

This works the same as the github authentication. It checks if the user has already authenticated; if not, redirect to the `Twitter authentication page`. The only differences between github and Twitter authentication are the endpoint to fetch user=data and the key to get the username from the fetched data

| | GitHub | Twitter |
|- |- |- |
| Endpoint to fetch user data | /user | account/settings.json |
| key for username | login | screen_name |

We have now completed authentication with GitHub and Twitter. Now let's create an application that can manage user sessions by `logging in` and `logging-out` the user.  

We will use Flask-login to manage user sessions and Flask-Sqlalchemy to store user as well as OAuth data.

### Setting up Flask-Login
#### Project Structure

```bash
.
├── app
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   └── oauth.py
├── main.py
├── requirements.txt
├── templates
│   ├── _base.html
│   └── index.html
└── users.db
```

Start by installing all the required dependencies.


```bash
pip install Flask-Login==0.5.0 Flask-SQLAlchemy==2.4.4
```

Start by creating the models to store user and OAuth information,

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

This will create two tables, `user` and `flask_dance_oauth`. The tables look like,

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

`OAuthConsumerMixin` will automatically add the necessary fields to store OAuth information. The login manager will fetch users from the `User` table.

### Setting up GitHub Login

Now we modify the github blueprint created earlier to add the `OAuth` table as storage.

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

Here, we passed storage as SQLAlchemy storage with the table as `OAuth`, passed in db.session(sqlalchemy.session) and the user as `current_user` from flask_login.

Now, we define the endpoints such as `login`, `logout`, and `homepage`.

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
After creating a new flask app, we initialize the `db` and `login_manager` defined earlier in `models.py`. 

The `homepage` view will render the `index.html` template. We'll get to the template soon. Next, we have a `/github` route that authenticates with github and returns the username. The `logout` route logs out the user.

All the routes are now setup. But we haven't logged in the user yet. For that, we use [Flask Signals](https://flask.palletsprojects.com/en/1.1.x/signals/). Signals allow you to perform certain actions when certain events(predefined) occurs. In our case, we'll log in the user when the github authentication is successful.

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

> blinker library is required for signals to work.
> pip install blinker==1.4

When the user connects via the `github_blueprint`, the `github_logged_in` function gets executed. It takes in two parameters: the blueprint and the token(from github). We grab the username from the provider and perform one of two actions.

1. If the username is already present in the tables, we log in the user
2. If not, we create a new user

Finally, we add the templates to finish our GitHub login.

```bash
mkdir templates && cd templates
touch _base.html
touch index.html
```

The _base.html contains the general layout. Add the following to it.

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

Now add a `login with GitHub` button to `index.html`

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

Once done, start the app and try it out at `http://127.0.0.1:5000`.

#### Demo

![demo 2](images/github-login.gif)


### Setting up Twitter Login

Create a Twitter blueprint and setup flask sqlalchemy as storage. Add the following to the `app.oauth.py` file.

```python
# app/oauth.py

twitter_blueprint = make_twitter_blueprint(
    api_key=os.getenv("TWITTER_API_KEY"),
    api_secret=os.getenv("TWITTER_API_SECRET"),
    storage=SQLAlchemyStorage(
        OAuth,
        db.session,
        user=current_user,
        user_required=False,
    ),
)
```

Here we created a Twitter blueprint just as we did for github. Now we need to create a route for Twitter login and flask-signal for creating sessions for Twitter login. Instead of repeating the code for each provider, we can write code to load the provider dynamically and log in. For this, we need to define the URLs and KEYs associated with the providers that we're using.

Add the following to `app/config.py`

```python
# app.config.py

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
```

The `providers` dict can now return data according to the provider we need. The `app` key returns the app, the `url` keys define the `endpoint` to call for user data, and the `user_key` is the dictionary key to get the username from the returned data(from the endpoint).

Let's change our `login` view to authenticate a provider given as a path parameter.

```python
# main.py

from app.config import providers

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
```

Compare this version of the login view with the previous one we wrote for github alone. You'll understand the changes.

Now we change the signals to work the same way. Modify the signal in `app/oauth.py` to,

```python
# app/oauth.py

from app.config import providers

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
```

Since `blueprint` is an argument to the signal, we'll extract the provider name using `blueprint.name`. Rest is same as the `login` view. Finally, we add a `Login with Twitter` button to `index.html`. Since we accept the provider as a path parameter, the old URL,    

`<a href="{{url_for('login')}}"></a>` becomes `{{url_for('login', provider='twitter')}}`

```html

...

{% else %}
    <a href="{{url_for('login', provider='github')}}"  class="btn btn-secondary">
        <i class="fa fa-github fa-fw"></i>
        <span>Login with GitHub</span>
    </a>
    
    <a href="{{url_for('login', provider='twitter')}}"  class="btn btn-primary">
        <i class="fa fa-twitter fa-fw"></i>
        <span>Login with Twitter</span>
    </a>
{% endif %}

...
```

Start the application and test it at https://127.0.0.1:5000

> If you face any troubles, delete the `users.db` and restart the app.

#### Demo

![demo 3](images/final-app.gif)

## Conclusion

In this tutorial, we have seen how to implement Social login for your flask application using Flask-dance. Once we set up GitHub login, the Twitter login was easy and was done in 5 steps (thanks to the simple flask-dance API). 

If you are looking for more challenges, figure out how to link multiple social media logins to a single account, get more data (email, language, country), etc., by specifying OAuth scopes. 