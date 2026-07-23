import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this"
)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///market.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )
    password_hash = db.Column(
        db.String(255),
        nullable=False
    )
    balance = db.Column(
        db.Integer,
        nullable=False,
        default=1000000
    )


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("main"))

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template(
            "login.html",
            message="아이디와 비밀번호를 입력하세요."
        )

    user = User.query.filter_by(username=username).first()

    if user is None:
        return render_template(
            "login.html",
            message="아이디 또는 비밀번호가 올바르지 않습니다."
        )

    if not check_password_hash(user.password_hash, password):
        return render_template(
            "login.html",
            message="아이디 또는 비밀번호가 올바르지 않습니다."
        )

    session.clear()
    session["user_id"] = user.id

    return redirect(url_for("main"))


@app.route("/main")
def main():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("index"))

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return redirect(url_for("index"))

    return render_template(
        "main.html",
        username=user.username,
        balance=user.balance
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    password_confirm = request.form.get(
        "password_confirm",
        ""
    )

    if not username or not password or not password_confirm:
        return render_template(
            "register.html",
            message="모든 항목을 입력하세요."
        )

    if password != password_confirm:
        return render_template(
            "register.html",
            message="비밀번호와 비밀번호 확인이 일치하지 않습니다."
        )

    existing_user = User.query.filter_by(
        username=username
    ).first()

    if existing_user:
        return render_template(
            "register.html",
            message="이미 사용 중인 아이디입니다."
        )

    password_hash = generate_password_hash(password)

    new_user = User(
        username=username,
        password_hash=password_hash,
        balance=1000000
    )

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for("index"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
