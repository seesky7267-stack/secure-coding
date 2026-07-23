from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    return f"입력된 아이디: {username}, 비밀번호: {password}"


@app.route("/register")
def register():
    return "회원가입 페이지는 다음 단계에서 만듭니다."


if __name__ == "__main__":
    app.run(debug=True)
