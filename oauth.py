import os
import requests
from dotenv import load_dotenv
from urllib.parse import parse_qs

load_dotenv()

AUTHORIZATION_ENDPOINT = f"https://github.com/login/oauth/authorize?response_type=code&client_id={os.getenv('GITHUB_ID')}"
TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
USER_ENDPOINT = "https://api.github.com/user"


print(f"Authorization URL: {AUTHORIZATION_ENDPOINT}")

code = input("Enter the code: ")

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

user_data = requests.get(USER_ENDPOINT, headers=dict(Authorization=f"token {token}"))

username = user_data.json()["login"]

print(f"You are {username} on GitHub")