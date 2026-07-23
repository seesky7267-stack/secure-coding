import os
import uuid

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
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this"
)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///market.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path,
    "static",
    "uploads"
)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}


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


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(
        db.String(100),
        nullable=False
    )
    price = db.Column(
        db.Integer,
        nullable=False
    )
    image_filename = db.Column(
        db.String(255),
        nullable=False
    )
    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )
    is_sold = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
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

    products = Product.query.order_by(Product.id.desc()).all()

    return render_template(
        "main.html",
        username=user.username,
        balance=user.balance,
        products=products
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


@app.route("/products/register", methods=["GET", "POST"])
def product_register():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("index"))

    if request.method == "GET":
        return render_template("product_register.html")

    name = request.form.get("name", "").strip()
    price_text = request.form.get("price", "").strip()
    image = request.files.get("image")

    if not name or not price_text or image is None:
        return render_template(
            "product_register.html",
            message="모든 항목을 입력하세요."
        )

    try:
        price = int(price_text)
    except ValueError:
        return render_template(
            "product_register.html",
            message="상품 금액은 숫자로 입력하세요."
        )

    if price <= 0:
        return render_template(
            "product_register.html",
            message="상품 금액은 1원 이상이어야 합니다."
        )

    if image.filename == "":
        return render_template(
            "product_register.html",
            message="상품 사진을 선택하세요."
        )

    if not allowed_file(image.filename):
        return render_template(
            "product_register.html",
            message="jpg, jpeg, png, webp 파일만 업로드할 수 있습니다."
        )

    original_filename = secure_filename(image.filename)
    extension = original_filename.rsplit(".", 1)[1].lower()
    saved_filename = f"{uuid.uuid4().hex}.{extension}"

    image_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        saved_filename
    )

    image.save(image_path)

    new_product = Product(
        name=name,
        price=price,
        image_filename=saved_filename,
        seller_id=user_id,
        is_sold=False
    )

    db.session.add(new_product)
    db.session.commit()

    return redirect(url_for("main"))

@app.route("/search")
def search():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("index"))

    keyword = request.args.get("keyword", "").strip()

    if not keyword:
        products = []
    else:
        products = (
            Product.query
            .filter(Product.name.contains(keyword))
            .order_by(Product.id.desc())
            .all()
        )

    return render_template(
        "search.html",
        keyword=keyword,
        products=products
    )   

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
