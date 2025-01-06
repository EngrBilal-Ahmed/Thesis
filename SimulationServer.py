from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/authenticate", methods=["POST"])
def authenticate():
    data = request.json
    # Perform authentication logic here
    return jsonify({"status": "success", "message": "User authenticated"})

if __name__ == "__main__":
    app.run(host="172.19.121.189", port=5000)
