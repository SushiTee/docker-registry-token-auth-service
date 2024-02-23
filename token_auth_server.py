"""Simple token authentication server for Docker registry"""

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
from config import config

try:
    from uwsgidecorators import postfork

    CAN_USE_UWSGI_DECORATORS = True
except ImportError:
    CAN_USE_UWSGI_DECORATORS = False

if CAN_USE_UWSGI_DECORATORS:

    @postfork
    def run_preconditions():
        """Run preconditions after forking in uWSGI."""
        check_config_available()


def check_config_available():
    """Check if all required config files are available."""
    if not os.path.exists("config" + os.sep + "config.py"):
        raise FileNotFoundError("users.json not found")
    if not os.path.exists("config" + os.sep + "users.json"):
        raise FileNotFoundError("users.json not found")
    if not os.path.exists("config" + os.sep + "repositories.json"):
        raise FileNotFoundError("repositories.json not found")
    if not os.path.exists(config.KEY_PATH):
        raise FileNotFoundError(f"{config.KEY_PATH} not found")


def extract_public_key_ind_der_format(private_key_path):
    """Extract public key from private key in DER format."""
    with open(private_key_path, "rb") as key_file:
        key_data = key_file.read()

    # Load the EC private key
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,  # You may need to provide a password if the key is encrypted
        backend=default_backend(),
    )

    # Extract the public key
    public_key = private_key.public_key()

    # Serialize the public key to DER format
    der_data = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return der_data


def key_id_encode(the_bytes):
    """Encode key in special format."""
    source = base64.b32encode(the_bytes).decode(encoding="utf-8").rstrip("=")
    result = []
    for i in range(0, len(source), 4):
        start = i
        end = start + 4
        result.append(source[start:end])
    return ":".join(result)


def kid_from_crypto_key():
    """
    python implementation of
    https://github.com/jlhawn/libtrust/blob/master/util.go#L192
    returns a distinct identifier which is unique to
    the public key derived from this private key.
    The format generated by this library is a base32 encoding of a 240 bit
    hash of the public key data divided into 12 groups like so:
    ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP
    """
    algorithm = hashlib.sha256()
    der = extract_public_key_ind_der_format(config.KEY_PATH)

    algorithm.update(der)
    return key_id_encode(algorithm.digest()[:30])


def authenticate(username, password):
    """Authenticate user and return user object if successful, else return None."""
    # Load users from JSON file
    with open("config" + os.sep + "users.json", "r", encoding="utf-8") as f:
        users = json.load(f)
        user = users.get(username)
        if user and bcrypt.checkpw(password.encode(), user["pass_hash"].encode()):
            return user


def actions_by_repository(repository):
    """Returns allowed actions for a repository based on the repository name."""
    with open("config" + os.sep + "repositories.json", "r", encoding="utf-8") as f:
        repositories = json.load(f)

        # if backlist is enabled, deny access if the requested repository is listed
        if repository in repositories["repositories"]:
            return [] if repositories.get("backlist", False) else ["pull"]
        return [] if not repositories.get("backlist", False) else ["pull"]  # whitelist


def check_scope(scope, user_data):
    """Build access list based on requested scope and user data."""
    if not scope:
        return {}

    _type = ""
    _name = ""
    _actions = ["*"]
    scope_data = scope.split(":")

    # don't care about those kind of scopes
    if len(scope_data) <= 1:
        return {}

    _type = scope_data[0]
    _name = scope_data[1]
    if _type == "repository":
        if not user_data:
            return {
                "type": _type,
                "name": _name,
                "actions": actions_by_repository(_name),
            }
        if _name in user_data["repositories"]:
            _actions = user_data["repositories"][_name]
        elif "*" in user_data["repositories"]:
            _actions = user_data["repositories"]["*"]
        else:
            _actions = actions_by_repository(_name)
    return {"type": _type, "name": _name, "actions": _actions}


def generate_token(username, user_data, service, scope):
    """Generate JWT token for user."""

    # get data from scope
    access = check_scope(scope, user_data)

    payload = {
        "iss": config.ISSUER,
        "sub": username,
        "aud": service,
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=30)).timestamp()),
        "nbf": int(datetime.now(timezone.utc).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": str(uuid.uuid4()),  # You should generate a unique JTI here
        "access": [access],
    }

    with open(config.KEY_PATH, "r", encoding="utf-8") as f:
        secret_key = f.read()
        jqt_token = jwt.encode(
            payload,
            secret_key,
            algorithm="ES256",
            headers={"kid": kid_from_crypto_key()},
        )

        return jqt_token


app = Flask(__name__)


@app.route("/v2/token")
def token():
    """Return JWT token for user."""
    service = request.args.get("service")
    scope = request.args.get("scope")
    # check if authorization header is present
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        jwt_token = generate_token("anon", None, service, scope)
        return jsonify({"token": jwt_token})

    username = request.authorization.username
    password = request.authorization.password

    user = authenticate(username, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    jwt_token = generate_token(username, user, service, scope)
    return jsonify({"token": jwt_token})


if __name__ == "__main__":
    check_config_available()
    app.run(port=config.PORT)