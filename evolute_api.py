import os
import json
import time
import logging
import threading
from flask import Flask, request, jsonify, abort
from datetime import datetime

LISTEN = os.getenv("LISTEN", "127.0.0.1")
PORT = int(os.getenv("PORT", 12321))
API_KEY = os.getenv("API_KEY", "change_me")
TIMEOUT = int(os.getenv("TIMEOUT", 60))
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", 600))
JSON_SUB = os.getenv("JSON_SUB", ".sensors.sensorsData")
EVOLUTE_TOKEN_FILENAME = os.getenv("EVOLUTE_TOKEN_FILENAME", "evy-platform-access.txt")
EVOLUTE_REFRESH_TOKEN_FILENAME = os.getenv("EVOLUTE_REFRESH_TOKEN_FILENAME", "evy-platform-refresh.txt")
CAR_ID = os.getenv("CAR_ID", "SOME_CAR_ID_HASH_CHANGE_ME")

DUMP_FILE = "dump.json"
STATUS_FILE = "status.json"

EVOLUTE_REFRESH_URL = "https://app.evassist.ru/id-service/auth/refresh-token"
EVOLUTE_SENSOR_URL = f"https://app.evassist.ru/car-service/tbox/{CAR_ID}/info"

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

sensors_data = {}
status_info = {
    "start_time": datetime.utcnow().isoformat(),
    "last_token_update": None,
    "last_sensor_update": None,
}
tokens_ok = False
start_timestamp = time.time()

def read_json_file(filename, default=None):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except Exception:
        return default or {}

def write_json_file(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to write {filename}: {e}")

def load_token(filename):
    try:
        with open(filename, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def save_token(filename, token):
    with open(filename, "w") as f:
        f.write(token.strip())

def get_tokens():
    return {
        "access": load_token(EVOLUTE_TOKEN_FILENAME),
        "refresh": load_token(EVOLUTE_REFRESH_TOKEN_FILENAME),
    }

def update_status(key):
    status_info[key] = datetime.utcnow().isoformat()
    write_json_file(STATUS_FILE, status_info)

def refresh_tokens():
    global tokens_ok
    try:
        tokens = get_tokens()
        payload = {"refreshToken": tokens["refresh"]}
        response = requests.post(EVOLUTE_REFRESH_URL, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        save_token(EVOLUTE_TOKEN_FILENAME, data["accessToken"])
        save_token(EVOLUTE_REFRESH_TOKEN_FILENAME, data["refreshToken"])
        update_status("last_token_update")
        tokens_ok = True
        logger.info("Tokens refreshed successfully")
    except Exception as e:
        tokens_ok = False
        logger.error(f"Failed to refresh tokens: {e}")

def fetch_sensor_data():
    global sensors_data
    if not tokens_ok:
        logger.warning("Sensor data fetch skipped: tokens are not active")
        return
    try:
        tokens = get_tokens()
        cookies = {
            "evy-platform-access": tokens["access"],
            "evy-platform-refresh": tokens["refresh"]
        }
        response = requests.get(EVOLUTE_SENSOR_URL, cookies=cookies, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        keys = JSON_SUB.strip(".").split(".")
        for k in keys:
            data = data.get(k, {})
        sensors_data = data
        update_status("last_sensor_update")
        write_json_file(DUMP_FILE, sensors_data)
        logger.info("Sensor data updated")
    except Exception as e:
        logger.error(f"Failed to fetch sensor data: {e}")


def periodic_refresh():
    refresh_tokens()
    t = threading.Timer(REFRESH_INTERVAL, periodic_refresh)
    t.daemon = True
    t.start()

def periodic_fetch():
    fetch_sensor_data()
    t = threading.Timer(60, periodic_fetch)
    t.daemon = True
    t.start()

def check_auth(req):
    key = req.headers.get("X-API-Key") or req.args.get("api_key")
    if key != API_KEY:
        abort(jsonify({"error": "Unauthorized"}), 401)

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok"}), 200

@app.route("/status", methods=["GET"])
def status():
    uptime_seconds = time.time() - start_timestamp
    return jsonify({
        "alive": True,
        "uptime": uptime_seconds,
        "start_time": status_info["start_time"],
        "last_token_update": status_info["last_token_update"],
        "last_sensor_update": status_info["last_sensor_update"],
        "tokens_active": tokens_ok
    })

@app.route("/set_tokens", methods=["POST"])
def set_tokens():
    check_auth(request)
    data = request.get_json(force=True)
    access = data.get("access")
    refresh = data.get("refresh")
    if access:
        save_token(EVOLUTE_TOKEN_FILENAME, access)
    if refresh:
        save_token(EVOLUTE_REFRESH_TOKEN_FILENAME, refresh)
    return jsonify({"status": "tokens updated"})

@app.route("/manual_refresh", methods=["POST"])
def manual_refresh():
    check_auth(request)
    refresh_tokens()
    return jsonify({"status": "refreshed"})

@app.route("/sensors/all", methods=["GET"])
def get_all_sensors():
    check_auth(request)
    return jsonify(sensors_data)

@app.route("/sensors/<string:sensor_name>", methods=["GET"])
def get_single_sensor(sensor_name):
    check_auth(request)
    value = sensors_data.get(sensor_name)
    if value is None:
        return jsonify({"error": "sensor not found"}), 404
    return jsonify({sensor_name: value})

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed"}), 405

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled error: {e}")
    return jsonify({"error": "Internal Server Error"}), 500

import requests

if __name__ == "__main__":
    start_timestamp = time.time()

    sensors_data = read_json_file(DUMP_FILE, default={})
    loaded_status = read_json_file(STATUS_FILE, default={})
    status_info.update({k: v for k, v in loaded_status.items() if k in status_info})

    periodic_refresh()
    periodic_fetch()

    logger.info("App started")
    app.run(host=LISTEN, port=PORT)
