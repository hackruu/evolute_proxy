import os
import json
import time
import logging
import threading
import sys
import sqlite3
import requests
from flask import Flask, request, jsonify, abort
from werkzeug.exceptions import HTTPException
from datetime import datetime
from flask import Response
from urllib.parse import urljoin


LISTEN = os.getenv("LISTEN", "127.0.0.1")
PORT = int(os.getenv("PORT", 12321))
API_KEY = os.getenv("API_KEY", "change_me")
API_KEY_RW = os.getenv("API_KEY_RW", "change_me_rw")
TIMEOUT = int(os.getenv("TIMEOUT", 60))
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", 600))
SENSORS_REFRESH_INTERVAL = int(os.getenv("SENSORS_REFRESH_INTERVAL", 120))
JSON_SUB = os.getenv("JSON_SUB", ".sensors")
EVOLUTE_TOKEN_FILENAME = os.getenv("EVOLUTE_TOKEN_FILENAME", "evy-platform-access.txt")
EVOLUTE_REFRESH_TOKEN_FILENAME = os.getenv("EVOLUTE_REFRESH_TOKEN_FILENAME", "evy-platform-refresh.txt")
CAR_ID = os.getenv("CAR_ID", "SOME_CAR_ID_HASH_CHANGE_ME")

current_refresh_interval = REFRESH_INTERVAL

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/144.0.0.0 Safari/537.36"
)

DUMP_FILE = "dump.json"
STATUS_FILE = "status.json"

EVOLUTE_REFRESH_URL = "https://app.evassist.ru/id-service/auth/refresh-token"
EVOLUTE_SENSOR_URL = f"https://app.evassist.ru/car-service/tbox/{CAR_ID}/info"
EVOLUTE_TRAVELS_SEARCH_URL = f"https://app.evassist.ru/car-service/travels/search/{CAR_ID}"
EVOLUTE_TRAVELS_DETAILS_URL = f"https://app.evassist.ru/car-service/travels/details/{CAR_ID}"
EVOLUTE_TELEMETRY_COMMANDS_URL = "https://app.evassist.ru/client-bff-service/telemetry-commands"

# Опциональная серверная история снапшотов: путь к файлу SQLite.
# Пусто (по умолчанию) — история выключена, поведение прокси не меняется.
HISTORY_DB = os.getenv("HISTORY_DB", "")
HISTORY_RETENTION_DAYS = int(os.getenv("HISTORY_RETENTION_DAYS", 90))
TRAVELS_DEFAULT_LIMIT = 20

INTELLIGENT_ACTIONS = {
    "lock_close": ("centralLockingToggle", "centralLockingStatus", 1),
    "lock_open": ("centralLockingToggle", "centralLockingStatus", 0),
    "heating_off": ("heating", "climateStatus", 0),
    "heating_on": ("heating", "climateStatus", 1),
    "cooling_off": ("cooling", "climateStatus", 0),
    "cooling_on": ("cooling", "climateStatus", 1),
    "trunk_close": ("trunkOpen", "trunkStatus", 0),
    "trunk_open": ("trunkOpen", "trunkStatus", 1),
    "prepare_on": ("PREPARE", "ignitionStatus", 1),
    "prepare_off": ("CANCEL", "ignitionStatus", 0),
    "blink": ("blink", "ready", 1),
}


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
    if default is None:
        default = {}
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except Exception:
        return default

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
    global tokens_ok, current_refresh_interval
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

        if current_refresh_interval != REFRESH_INTERVAL:
            logger.info(f"Token refresh successful. Resetting interval to {REFRESH_INTERVAL}s")
            current_refresh_interval = REFRESH_INTERVAL
        else:
            logger.info("Tokens refreshed successfully")

    except requests.exceptions.HTTPError as e:
        tokens_ok = False
        if e.response is not None and e.response.status_code == 403:
            new_interval = min(current_refresh_interval * 2, 3600)
            logger.warning(f"403 Forbidden during token refresh. Increasing cooldown from {current_refresh_interval}s to {new_interval}s")
            current_refresh_interval = new_interval
        else:
            logger.error(f"HTTP error refreshing tokens: {e}")

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
        headers = {
            "User-Agent": USER_AGENT
        }
        response = requests.get(EVOLUTE_SENSOR_URL, headers=headers, cookies=cookies, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        keys = JSON_SUB.strip(".").split(".")
        for k in keys:
            data = data.get(k, {})
        sensors_data = data
        update_status("last_sensor_update")
        write_json_file(DUMP_FILE, sensors_data)
        append_history(sensors_data)
        logger.info("Sensor data updated")
    except Exception as e:
        logger.error(f"Failed to fetch sensor data: {e}")


# --- Серверная история снапшотов (опционально, HISTORY_DB) ---
# Каждый успешный fetch_sensor_data кладёт снапшот в SQLite. Клиент может
# забрать ряд задним числом через /history/sensors, даже пока приложение
# не запущено. Ключ строки — time из ответа облака (unix-секунды).

def append_history(snapshot):
    if not HISTORY_DB:
        return
    try:
        ts = int(snapshot.get("time") or time.time())
        conn = sqlite3.connect(HISTORY_DB, timeout=30)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS snapshots ("
                "ts INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT OR REPLACE INTO snapshots (ts, payload) VALUES (?, ?)",
                (ts, json.dumps(snapshot)),
            )
            conn.execute(
                "DELETE FROM snapshots WHERE ts < ?",
                (ts - HISTORY_RETENTION_DAYS * 86400,),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"History append failed: {e}")


def get_history(from_ts, to_ts, limit):
    if not HISTORY_DB:
        return []
    try:
        conn = sqlite3.connect(HISTORY_DB, timeout=30)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS snapshots ("
                "ts INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
            )
            rows = conn.execute(
                "SELECT payload FROM snapshots "
                "WHERE ts >= ? AND ts <= ? ORDER BY ts ASC LIMIT ?",
                (from_ts, to_ts, limit),
            ).fetchall()
        finally:
            conn.close()
        return [json.loads(payload) for (payload,) in rows]
    except Exception as e:
        logger.error(f"History read failed: {e}")
        return []


def travels_search_body(raw):
    """Дефолты для /travels/search: пустой body -> вся история, последние поездки."""
    raw = raw if isinstance(raw, dict) else {}
    return {
        "filters": raw.get("filters") or [{"key": "PERIOD", "values": ["ALL"]}],
        "limit": raw.get("limit", TRAVELS_DEFAULT_LIMIT),
        "offset": raw.get("offset", 0),
        "sort": raw.get("sort") or {"by": "DATE", "dir": "DESC"},
    }


def upstream_json(method, url, **kw):
    """Запрос к облаку с токенами; статус и body апстрима проходят как есть."""
    tokens = get_tokens()
    headers = kw.pop("headers", None) or {"User-Agent": USER_AGENT}
    headers.setdefault("User-Agent", USER_AGENT)
    cookies = {
        "evy-platform-access": tokens["access"],
        "evy-platform-refresh": tokens["refresh"],
    }
    try:
        resp = requests.request(
            method, url, headers=headers, cookies=cookies, timeout=TIMEOUT, **kw
        )
        return Response(
            resp.content,
            resp.status_code,
            content_type=resp.headers.get("Content-Type", "application/json"),
        )
    except Exception as e:
        logger.error(f"Upstream {method} {url} failed: {e}")
        return Response(
            json.dumps({"error": "Upstream request failed"}),
            502,
            content_type="application/json",
        )

def periodic_refresh():
    refresh_tokens()
    t = threading.Timer(current_refresh_interval, periodic_refresh)
    t.daemon = True
    t.start()

def periodic_fetch():
    fetch_sensor_data()
    t = threading.Timer(SENSORS_REFRESH_INTERVAL, periodic_fetch)
    t.daemon = True
    t.start()

def check_auth(req):
    key = req.headers.get("X-API-Key") or req.args.get("api_key")
    if key != API_KEY:
        abort(401)

def check_auth_rw(req):
    key = req.headers.get("X-API-Key") or req.args.get("api_key")
    if key != API_KEY_RW:
        abort(401)

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
        "tokens_active": tokens_ok,
        "current_refresh_interval": current_refresh_interval,
        "history_enabled": bool(HISTORY_DB)
    })

@app.route("/set_tokens", methods=["POST"])
def set_tokens():
    global current_refresh_interval
    check_auth(request)
    data = request.get_json(force=True)
    access = data.get("access")
    refresh = data.get("refresh")
    if access:
        save_token(EVOLUTE_TOKEN_FILENAME, access)
    if refresh:
        save_token(EVOLUTE_REFRESH_TOKEN_FILENAME, refresh)

    current_refresh_interval = REFRESH_INTERVAL

    return jsonify({"status": "tokens updated"})

@app.route("/manual_refresh", methods=["POST"])
def manual_refresh():
    check_auth(request)
    refresh_tokens()
    return jsonify({"status": "refreshed", "interval": current_refresh_interval})

@app.route("/sensors/all", methods=["GET"])
def get_all_sensors():
    check_auth(request)
    sensors = sensors_data.get("sensorsData")
    if sensors:
        return jsonify(sensors)
    else:
        return jsonify({"error": "No sensors data available"}), 404

@app.route("/position/all", methods=["GET"])
def get_all_positions():
    check_auth(request)
    position = sensors_data.get("positionData")
    if position:
        return jsonify(position)
    else:
        return jsonify({"error": "No position data available"}), 404

@app.route("/sensors/<string:sensor_name>", methods=["GET"])
def get_single_sensor(sensor_name):
    check_auth_rw(request)
    value = sensors_data.get(sensor_name)
    if value is None:
        return jsonify({"error": "sensor not found"}), 404
    return jsonify({sensor_name: value})

@app.route("/proxy/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def proxy(subpath):
    check_auth_rw(request)
    tokens = get_tokens()
    base_url = "https://app.evassist.ru/"
    target_url = urljoin(base_url, subpath)

    method = request.method
    headers = {
        "User-Agent": USER_AGENT
    }
    headers.update({
        k: v for k, v in request.headers.items()
        if k.lower() not in ["host", "content-length", "content-type", "x-api-key"]
    })

    if request.content_type:
        headers["Content-Type"] = request.content_type

    cookies = {
        "evy-platform-access": tokens["access"],
        "evy-platform-refresh": tokens["refresh"]
    }

    try:
        resp = requests.request(
            method,
            target_url,
            headers=headers,
            params=request.args,
            data=request.get_data(),
            cookies=cookies,
            timeout=TIMEOUT,
            allow_redirects=False
        )
        excluded_headers = ["content-encoding", "transfer-encoding", "connection"]
        response_headers = [
            (name, value) for (name, value) in resp.raw.headers.items()
            if name.lower() not in excluded_headers
        ]
        return Response(resp.content, resp.status_code, response_headers)
    except Exception as e:
        logger.error(f"Proxy request failed: {e}")
        return jsonify({"error": "Proxy failed"}), 500

@app.route("/travels/search", methods=["POST"])
def travels_search():
    """История поездок (passthrough к /car-service/travels/search/<CAR_ID>).

    Body полностью опционален; недостающее дополняется дефолтами:
      {"filters": [{"key": "PERIOD", "values": ["ALL"]}],   # или DATE_START/DATE_END (epoch ms)
       "limit": 20, "offset": 0, "sort": {"by": "DATE", "dir": "DESC"}}
    Ответ облака проходит как есть: {"rows": [...], "total", "offset", "limit"}.
    """
    check_auth(request)
    raw = request.get_json(silent=True) or {}
    payload = travels_search_body(raw)
    return upstream_json("POST", EVOLUTE_TRAVELS_SEARCH_URL, json=payload)


@app.route("/travels/details/<int:trip_id>", methods=["GET"])
def travels_details(trip_id):
    """Детали поездки с GPS-треком (passthrough к .../travels/details/<CAR_ID>/<id>).

    Обязателен ?startTime=<segmentStartTime из /travels/search> (unix-секунды),
    иначе облако отвечает ValidateError. Ответ содержит points: [{lat, lon, time}].
    """
    check_auth(request)
    start = request.args.get("startTime")
    if start is None:
        return jsonify({"error": "startTime is required (segmentStartTime from /travels/search)"}), 400
    return upstream_json(
        "GET", f"{EVOLUTE_TRAVELS_DETAILS_URL}/{trip_id}", params={"startTime": start}
    )


@app.route("/telemetry-commands", methods=["POST"])
def telemetry_command_create():
    """Официальный command-queue облака: POST -> {"commandId": ...}.

    Body passthrough: {"commandName": str, "imei": str, "value": ...} — это
    РЕАЛЬНАЯ команда на машину, поэтому ключ RW. Статус исполнения: проверить
    GET /telemetry-commands/<commandId> (ключ RO).
    """
    check_auth_rw(request)
    headers = {"User-Agent": USER_AGENT}
    if request.content_type:
        headers["Content-Type"] = request.content_type
    return upstream_json(
        "POST", EVOLUTE_TELEMETRY_COMMANDS_URL, headers=headers, data=request.get_data()
    )


@app.route("/telemetry-commands/<command_id>", methods=["GET"])
def telemetry_command_status(command_id):
    check_auth(request)
    return upstream_json("GET", f"{EVOLUTE_TELEMETRY_COMMANDS_URL}/{command_id}")


@app.route("/history/sensors", methods=["GET"])
def history_sensors():
    """Серверная история снапшотов (нужен запущенный HISTORY_DB).

    ?from=<unix-sec>&to=<unix-sec>&limit=<n>; по умолчанию последние 24 ч.
    Ряды — те же объекты, что пишет dump.json: {time, sensorsData, positionData}.
    """
    check_auth(request)
    if not HISTORY_DB:
        return jsonify({"error": "history disabled: set HISTORY_DB"}), 400
    to_raw = request.args.get("to", type=int)
    from_raw = request.args.get("from", type=int)
    to_ts = to_raw if to_raw is not None else int(time.time())
    from_ts = from_raw if from_raw is not None else (to_ts - 86400)
    limit = min(request.args.get("limit", type=int) or 10_000, 100_000)
    return jsonify({"rows": get_history(from_ts, to_ts, limit)})


@app.route("/tbox/<string:action>", methods=["POST"])
def tbox_action(action):
    check_auth_rw(request)
    tokens = get_tokens()
    target_url = f"https://app.evassist.ru/car-service/tbox/{CAR_ID}/{action}"

    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json"
    }

    cookies = {
        "evy-platform-access": tokens["access"],
        "evy-platform-refresh": tokens["refresh"]
    }

    try:
        resp = requests.post(
            target_url,
            headers=headers,
            data=request.get_data(),
            cookies=cookies,
            timeout=TIMEOUT
        )
        resp.raise_for_status()
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"TBox action request failed: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/tbox-i/<string:action>", methods=["POST"])
def tbox_i_action(action):
    check_auth_rw(request)

    if action not in INTELLIGENT_ACTIONS:
        return jsonify({"status": "error", "error": f"Unknown intelligent action: {action}"}), 400

    endpoint, status_key, skip_if_value = INTELLIGENT_ACTIONS[action]

    try:
        fetch_sensor_data()
        current_value = sensors_data.get("sensorsData", {}).get(status_key)

        if current_value == skip_if_value:
            logger.info(f"Intelligent action '{action}' skipped: already in desired state")
            return jsonify({"status": "already_ok"})

        target_url = f"https://app.evassist.ru/car-service/tbox/{CAR_ID}/{endpoint}"
        tokens = get_tokens()
        headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json"
        }
        cookies = {
            "evy-platform-access": tokens["access"],
            "evy-platform-refresh": tokens["refresh"]
        }

        resp = requests.post(
            target_url,
            headers=headers,
            data=request.get_data(),
            cookies=cookies,
            timeout=TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Intelligent action '{action}' executed successfully")
        fetch_sensor_data()

        return jsonify({"status": "success"})

    except Exception as e:
        logger.error(f"Intelligent action '{action}' failed: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed"}), 405

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    return jsonify({"error": e.description}), e.code

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled error: {e}")
    return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    if CAR_ID == "SOME_CAR_ID_HASH_CHANGE_ME":
        logger.error("Critical environment variable CAR_ID is not set. Exiting.")
        sys.exit(1)

    start_timestamp = time.time()

    sensors_data = read_json_file(DUMP_FILE, default={})
    loaded_status = read_json_file(STATUS_FILE, default={})
    status_info.update({k: v for k, v in loaded_status.items() if k in status_info})

    periodic_refresh()
    periodic_fetch()

    logger.info("App started")
    app.run(host=LISTEN, port=PORT)
