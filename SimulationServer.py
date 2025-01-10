from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/authenticate", methods=["POST"])
def authenticate():
    data = request.json
    # Perform authentication logic here
    b = 2+6
    return jsonify({"status": "success", "message": "User authenticated","Value": b})

if __name__ == "__main__":
    #app.run(host="172.19.121.189", port=5000)
    app.run(host="localhost", port=5000)
