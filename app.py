from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "중고거래 플랫폼 서버가 정상적으로 실행되었습니다."


if __name__ == "__main__":
    app.run(debug=True)
