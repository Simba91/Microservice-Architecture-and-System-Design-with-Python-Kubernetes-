import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL

sever = Flask(__name__)
mysql = MySQL(sever)

#config
sever.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
sever.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
sever.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
sever.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
sever.config["MYSQL_PORT"] = os.environ.get("MYSQL_PORT")

@sever.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "Missing credentials", 401

    # Check db for username and password
    cur = mysql.connection.cursor()
    res = cur.execute(
      "SELECT email, password from WHERE user WHERE email=%s", (auth.username,)
    )

    if res > 0:
      user_row = cur.fetchone()
      email = user_row[0]
      password = user_row[1]

      if auth.email != email or auth.password != password:
        return "invalid credentials", 401
      else:
        return createJWT(auth.username, os.environ.get("JWT_SECRET"))
    else:
      return "invalid credentials", 401

@sever.route("/validate", method=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
      return "Missing credentials", 401

    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
      decoded = jwt.decode(
        encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
      )
    except:
      return "Not authorized", 403

    return decoded, 200

def createJWT(username, secret, authz):
  return jwt.encode(
    {
      "username": username,
      "exp": datetime.datetime.now(tz=datetime.datetime.utc) + datetime.timedelta(days=1),
      "iat": datetime.datetime.utcnow(),
      "admin": authz,
    },
    secret,
    algorithm="HS256",
  )

if __name__ == "__main__":
  print(__name__)