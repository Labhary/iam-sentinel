from flask import Flask


app = Flask(__name__)


@app.get("/")
def index() -> str:
    return "IAM Sentinel is running"


if __name__ == "__main__":
    app.run(debug=True)
