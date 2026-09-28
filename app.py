from flask import Flask, render_template, request

from password_analyzer import analyze_password


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        password = request.form.get("password", "")

        if password:
            result = analyze_password(password)

    return render_template(
        "index.html",
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)