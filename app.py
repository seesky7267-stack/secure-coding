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
ADMIN_USERNAME = "admin"


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


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(
        db.String(300),
        nullable=False
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )
    product_id = db.Column(
        db.Integer,
        db.ForeignKey("product.id"),
        nullable=False
    )


class BlockedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        unique=True,
        nullable=False
    )


class BlockedProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(
        db.Integer,
        db.ForeignKey("product.id"),
        unique=True,
        nullable=False
    )


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    return db.session.get(User, user_id)


def is_admin(user):
    return user is not None and user.username == ADMIN_USERNAME


def user_is_blocked(user_id):
    return BlockedUser.query.filter_by(user_id=user_id).first() is not None


def product_is_blocked(product_id):
    return (
        BlockedProduct.query
        .filter_by(product_id=product_id)
        .first()
        is not None
    )


def visible_products_query():
    blocked_user_ids = db.session.query(BlockedUser.user_id)
    blocked_product_ids = db.session.query(BlockedProduct.product_id)

    return Product.query.filter(
        ~Product.seller_id.in_(blocked_user_ids),
        ~Product.id.in_(blocked_product_ids)
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

    if user is None or not check_password_hash(
        user.password_hash,
        password
    ):
        return render_template(
            "login.html",
            message="아이디 또는 비밀번호가 올바르지 않습니다."
        )

    if user_is_blocked(user.id):
        return render_template(
            "login.html",
            message="차단된 계정입니다."
        )

    session.clear()
    session["user_id"] = user.id

    return redirect(url_for("main"))


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
            message="비밀번호가 일치하지 않습니다."
        )

    if User.query.filter_by(username=username).first():
        return render_template(
            "register.html",
            message="이미 사용 중인 아이디입니다."
        )

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        balance=1000000
    )

    db.session.add(user)
    db.session.commit()

    return redirect(url_for("index"))


@app.route("/main")
def main():
    user = current_user()

    if user is None:
        return redirect(url_for("index"))

    if user_is_blocked(user.id):
        session.clear()
        return redirect(url_for("index"))

    products = (
        visible_products_query()
        .order_by(Product.id.desc())
        .all()
    )

    return render_template(
        "main.html",
        username=user.username,
        balance=user.balance,
        products=products,
        is_admin=is_admin(user)
    )


@app.route("/products/register", methods=["GET", "POST"])
def product_register():
    user = current_user()

    if user is None:
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

    if not image.filename or not allowed_file(image.filename):
        return render_template(
            "product_register.html",
            message="jpg, jpeg, png, webp 파일만 가능합니다."
        )

    original_filename = secure_filename(image.filename)
    extension = original_filename.rsplit(".", 1)[1].lower()
    saved_filename = f"{uuid.uuid4().hex}.{extension}"

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    image.save(
        os.path.join(
            app.config["UPLOAD_FOLDER"],
            saved_filename
        )
    )

    product = Product(
        name=name,
        price=price,
        image_filename=saved_filename,
        seller_id=user.id,
        is_sold=False
    )

    db.session.add(product)
    db.session.commit()

    return redirect(url_for("main"))


@app.route("/search")
def search():
    user = current_user()

    if user is None:
        return redirect(url_for("index"))

    keyword = request.args.get("keyword", "").strip()

    if keyword:
        products = (
            visible_products_query()
            .filter(Product.name.contains(keyword))
            .order_by(Product.id.desc())
            .all()
        )
    else:
        products = []

    return render_template(
        "search.html",
        keyword=keyword,
        products=products
    )


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    user = current_user()

    if user is None:
        return redirect(url_for("index"))

    product = db.session.get(Product, product_id)

    if product is None or product_is_blocked(product_id):
        return "존재하지 않거나 차단된 상품입니다.", 404

    if user_is_blocked(product.seller_id):
        return "차단된 사용자의 상품입니다.", 404

    comments = (
        db.session.query(Comment, User)
        .join(User, Comment.user_id == User.id)
        .filter(Comment.product_id == product.id)
        .filter(
            ~Comment.user_id.in_(
                db.session.query(BlockedUser.user_id)
            )
        )
        .order_by(Comment.id.asc())
        .all()
    )

    back_url = request.args.get("back_url")

    if not back_url:
        referrer = request.referrer

        if referrer and "/products/" not in referrer:
            back_url = referrer
        else:
            back_url = url_for("main")

    return render_template(
        "product_detail.html",
        product=product,
        user=user,
        comments=comments,
        back_url=back_url,
        message=request.args.get("message")
    )


@app.route(
    "/products/<int:product_id>/comments",
    methods=["POST"]
)
def add_comment(product_id):
    user = current_user()

    if user is None:
        return redirect(url_for("index"))

    product = db.session.get(Product, product_id)

    if product is None or product_is_blocked(product_id):
        return "존재하지 않는 상품입니다.", 404

    content = request.form.get("content", "").strip()
    back_url = request.form.get("back_url") or url_for("main")

    if not content:
        return redirect(
            url_for(
                "product_detail",
                product_id=product_id,
                back_url=back_url,
                message="댓글 내용을 입력하세요."
            )
        )

    if len(content) > 300:
        return redirect(
            url_for(
                "product_detail",
                product_id=product_id,
                back_url=back_url,
                message="댓글은 300자 이하로 입력하세요."
            )
        )

    comment = Comment(
        content=content,
        user_id=user.id,
        product_id=product.id
    )

    db.session.add(comment)
    db.session.commit()

    return redirect(
        url_for(
            "product_detail",
            product_id=product_id,
            back_url=back_url
        )
    )


@app.route(
    "/products/<int:product_id>/purchase",
    methods=["POST"]
)
def purchase_product(product_id):
    buyer = current_user()
    back_url = request.form.get("back_url") or url_for("main")

    if buyer is None:
        return redirect(url_for("index"))

    product = db.session.get(Product, product_id)

    if product is None or product_is_blocked(product_id):
        return "존재하지 않는 상품입니다.", 404

    if product.is_sold:
        message = "이미 판매 완료된 상품입니다."
    elif product.seller_id == buyer.id:
        message = "자신의 상품은 구매할 수 없습니다."
    elif buyer.balance < product.price:
        message = "잔액이 부족합니다."
    else:
        seller = db.session.get(User, product.seller_id)

        if seller is None:
            return "판매자를 찾을 수 없습니다.", 404

        buyer.balance -= product.price
        seller.balance += product.price
        product.is_sold = True

        db.session.commit()
        message = None

    return redirect(
        url_for(
            "product_detail",
            product_id=product.id,
            back_url=back_url,
            message=message
        )
    )


@app.route("/admin")
def admin():
    user = current_user()

    if not is_admin(user):
        return "관리자만 접근할 수 있습니다.", 403

    users = User.query.order_by(User.id.asc()).all()
    products = Product.query.order_by(Product.id.desc()).all()

    comments = (
        db.session.query(Comment, User, Product)
        .join(User, Comment.user_id == User.id)
        .join(Product, Comment.product_id == Product.id)
        .order_by(Comment.id.desc())
        .all()
    )

    blocked_user_ids = {
        item.user_id for item in BlockedUser.query.all()
    }
    blocked_product_ids = {
        item.product_id for item in BlockedProduct.query.all()
    }

    return render_template(
        "admin.html",
        users=users,
        products=products,
        comments=comments,
        blocked_user_ids=blocked_user_ids,
        blocked_product_ids=blocked_product_ids
    )


@app.route(
    "/admin/users/<int:user_id>/toggle-block",
    methods=["POST"]
)
def toggle_user_block(user_id):
    admin_user = current_user()

    if not is_admin(admin_user):
        return "관리자만 접근할 수 있습니다.", 403

    target = db.session.get(User, user_id)

    if target is None:
        return "사용자를 찾을 수 없습니다.", 404

    if target.username == ADMIN_USERNAME:
        return "관리자 계정은 차단할 수 없습니다.", 400

    blocked = BlockedUser.query.filter_by(user_id=user_id).first()

    if blocked:
        db.session.delete(blocked)
    else:
        db.session.add(BlockedUser(user_id=user_id))

    db.session.commit()

    return redirect(url_for("admin"))


@app.route(
    "/admin/products/<int:product_id>/toggle-block",
    methods=["POST"]
)
def toggle_product_block(product_id):
    admin_user = current_user()

    if not is_admin(admin_user):
        return "관리자만 접근할 수 있습니다.", 403

    product = db.session.get(Product, product_id)

    if product is None:
        return "상품을 찾을 수 없습니다.", 404

    blocked = (
        BlockedProduct.query
        .filter_by(product_id=product_id)
        .first()
    )

    if blocked:
        db.session.delete(blocked)
    else:
        db.session.add(BlockedProduct(product_id=product_id))

    db.session.commit()

    return redirect(url_for("admin"))


@app.route(
    "/admin/comments/<int:comment_id>/delete",
    methods=["POST"]
)
def delete_comment(comment_id):
    admin_user = current_user()

    if not is_admin(admin_user):
        return "관리자만 접근할 수 있습니다.", 403

    comment = db.session.get(Comment, comment_id)

    if comment is None:
        return "댓글을 찾을 수 없습니다.", 404

    db.session.delete(comment)
    db.session.commit()

    return redirect(url_for("admin"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
