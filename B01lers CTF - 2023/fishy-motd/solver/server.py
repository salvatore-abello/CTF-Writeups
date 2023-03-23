from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/lol", methods=["POST"])
def lol():
    credentials = request.form.get("credentials")
    print(f"{credentials = }")

    return "lol"


@app.route("/")
def index():
    return render_template("index.html")


app.run("0.0.0.0", 1337)
