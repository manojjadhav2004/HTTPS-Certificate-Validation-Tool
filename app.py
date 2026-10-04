"""Flask dashboard for the HTTPS Certificate Validation Tool.

    python app.py     ->     http://127.0.0.1:5000

Only meant for local use: it listens on 127.0.0.1 and connects to whatever host the user types in.
"""
from flask import Flask, jsonify, render_template, request

from cert_validator import validate
from utils.paths import LAB_CA_PATH

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
WEB_TIMEOUT = 8.0


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/validate")
def api_validate():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": {"kind": "invalid_input", "message": "Send a JSON body with a 'target' field."}}), 400

    port = data.get("port")
    if port in ("", None):
        port = None
    # The dashboard never accepts a file path from the browser; it can only switch the lab Root CA on or off.
    ca_file = str(LAB_CA_PATH) if data.get("use_lab_ca") else None

    report = validate(data.get("target"), port, ca_file=ca_file, timeout=WEB_TIMEOUT)
    status = 400 if report.error and report.error["kind"] == "invalid_input" else 200
    return jsonify(report.to_dict()), status


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
