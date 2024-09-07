import hashlib
import click
from flask import Flask, render_template, redirect, url_for, request
# integration med GitHub för att kunna autentisera användare via deras GitHub-konto.
from flask_dance.contrib.github import make_github_blueprint, github
# Hanterar användarsessioner (inloggning, utloggning, kontroll om användaren är inloggad).
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from hasher import hash_passwords
from flask.cli import with_appcontext
from password_cracker import find_password


# Används för att hantera miljövariabler,
# såsom OAuth-klienthemligheter och API-nycklar.
import os

# Tillåter Flask att köra via HTTP istället för HTTPS
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Skapar ny Flask-applikation
app = Flask(__name__)


# -------------  CONFIG ---------------

# Skyddar sessionsdata i Flask. Krypterar tex användarens sessionscookies
app.secret_key = "webdyx4vwvop7"

login_manager = LoginManager()
login_manager.login_view = "github.login"
# Kopplar LoginManager till Flask-applikationen
login_manager.init_app(app)

# GitHub OAuth config
github_blueprint = make_github_blueprint(
    client_id="Ov23lifr5seUidiNylrd",
    client_secret="00f7f186f96f27559cc0f3416197c60f287cccc6",
    redirect_to="github_login"
)

app.register_blueprint(github_blueprint, url_prefix='/github_login')


@login_manager.user_loader
def load_user(user_id):
    return User(username=user_id)


#  -----------   BASIC ROUTING  -----------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template("index.html", username=current_user.username)
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/github_login')
def github_login():
    if not github.authorized:
        return redirect(url_for("github.login"))

    try:
        response = github.get("/user")
        github_info = response.json()
        username = github_info.get("login", "Unknown")
        login_user(User(username=username))
    except OAuth2Error:
        return redirect(url_for("index"))

    return redirect(url_for('index'))


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


#  -----------   HASH ROUTING  -----------
@app.route('/hash')
@login_required
def hashing():
    return render_template('hashing.html')


@app.route('/getHash', methods=['POST'])
@login_required
def get_hash():
    input_string = request.form.get('input')

    if input_string:
        md5_hash = hashlib.md5(input_string.encode('utf-8')).hexdigest()
        sha256_hash = hashlib.sha256(input_string.encode('utf-8')).hexdigest()

        return render_template('hashing.html', input=input_string, md5=md5_hash, sha256=sha256_hash)
    return render_template('hashing.html', error="Please provide input to hash.")


# ---------- PASSWORD CRACKER ROUTING ----------
@app.route('/password_cracker')
@login_required
def cracking():
    return render_template('password-cracker.html')


@app.route('/crack', methods=['POST'])
@login_required
def crack_password():
    input_string = request.form.get('input')
    input_string = input_string.strip()
    found_password = find_password(input_string)
    if found_password is not None:
        return render_template('password-cracker.html', submitted=True, input=input_string,
                               cracked_password=found_password)
    return render_template('password-cracker.html', submitted=True, cracked_password=None)


# ----------  BASIC USER MODEL ----------
class User:
    def __init__(self, username):
        self.username = username

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.username


if __name__ == "__main__":
    app.run(debug=True)


@app.cli.command("hash-passwords")
@with_appcontext
def hash_passwords_command():
    """Hashes passwords when triggered via the Flask CLI."""
    print("Hashes passwords command...")
    hash_passwords('md5_hashes.txt', 'md5')
    hash_passwords('sha256_hashes.txt', 'sha256')
    print("Hashed passwords successfully.")