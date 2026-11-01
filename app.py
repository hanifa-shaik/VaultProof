from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "<h1>Welcome to TrustVault</h1><p>Your documents. Your permissions. Your proof.</p>"

if __name__ == "__main__":
    app.run(debug=True)