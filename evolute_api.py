import os
import json
import math
import time
import logging
import threading
import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import Flask, request, jsonify, abort
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
JSON_SUB = os.getenv("JSON_SUB", "")
EVOLUTE_TOKEN_FILENAME = os.getenv("EVOLUTE_TOKEN_FILENAME", "evy-platform-access.txt")
EVOLUTE_REFRESH_TOKEN_FILENAME = os.getenv("EVOLUTE_REFRESH_TOKEN_FILENAME", "evy-platform-refresh.txt")
# IMEI of the car's TBox — the numeric id in the telemetry URL,
# e.g. https://app.evassist.ru/client-bff-service/telemetry/<CAR_ID>
# (NOT the old hash-shaped car id from carV2/ links — that gets a 400 now)
CAR_ID = os.getenv("CAR_ID", "SOME_CAR_IMEI_CHANGE_ME")

current_refresh_interval = REFRESH_INTERVAL

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/159.0.0.0 Safari/537.36"
)

# Header set copied from the web app's own XHRs (Chrome 159 on macOS) so the
# polls look like the site's JS workers to any rate-limiter
BROWSER_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8,ru;q=0.7",
    "x-app": "web",
    "time-zone": "3",
    "sec-ch-ua": '"Google Chrome";v="159", "Not/A)Brand";v="8", "Chromium";v="159"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

DUMP_FILE = "dump.json"
STATUS_FILE = "status.json"

# The upstream LB (single IP) occasionally drops TCP connects. Retry the
# connect phase only — the request is never sent if the connection never
# opened, so even command POSTs are safe to retry. Read/status retries stay
# off: resending a command body could re-fire the action.
UPSTREAM_RETRIES = Retry(connect=2, read=0, status=0, other=0, backoff_factor=1)
upstream = requests.Session()
upstream.headers.update(BROWSER_HEADERS)
upstream.mount("https://", HTTPAdapter(max_retries=UPSTREAM_RETRIES))

# ETag of the last telemetry response; sent back as If-None-Match so unchanged
# data comes back as a tiny 304, exactly like the web app's polling
telemetry_etag = None

EVOLUTE_REFRESH_URL = "https://app.evassist.ru/id-service/auth/refresh-token"
EVOLUTE_TELEMETRY_URL = f"https://app.evassist.ru/client-bff-service/telemetry/{CAR_ID}"
EVOLUTE_COMMANDS_URL = "https://app.evassist.ru/client-bff-service/telemetry-commands"

# action: (command_name, status_source, skip_when)
# status_source: ("sensor", key in sensorsData) | ("button", activateCommand) | None
INTELLIGENT_ACTIONS = {
    "lock_close": ("centralLockingOn", ("sensor", "isCentralLockingOn"), True),
    "lock_open": ("centralLockingOff", ("sensor", "isCentralLockingOn"), False),
    "heating_on": ("heatingOn", ("button", "heatingOn"), True),
    "heating_off": ("heatingOff", ("button", "heatingOn"), False),
    "cooling_on": ("coolingOn", ("button", "coolingOn"), True),
    "cooling_off": ("coolingOff", ("button", "coolingOn"), False),
    "trunk_open": ("trunkOpen", ("sensor", "isTrunkOpen"), True),
    "trunk_close": ("trunkClose", ("sensor", "isTrunkOpen"), False),
    "prepare_on": ("PREPARE", ("sensor", "isIgnitionOn"), True),
    "prepare_off": ("CANCEL", ("sensor", "isIgnitionOn"), False),
    "blink": ("search", None, None),
}

# new upstream key -> legacy key kept so Home Assistant templates keep working
SENSOR_KEY_ALIASES = {
    "remainsFuelMileage": "remainsMileageFuel",
    "remainsBatteryMileage": "remainsMileage",
    "isCentralLockingOn": "centralLockingStatus",
    "isIgnitionOn": "ignitionStatus",
    "isTrunkOpen": "trunkStatus",
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
    global tokens_ok, current_refresh_interval
    try:
        tokens = get_tokens()
        payload = {"refreshToken": tokens["refresh"]}
        response = upstream.post(EVOLUTE_REFRESH_URL, json=payload, timeout=TIMEOUT)
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

def build_sensors_data(sensors, buttons=None):
    """Map the flat upstream `sensors` dict into the legacy shape HA expects:
    keep all new keys, add old-name aliases, coerce bools to ints, and
    re-synthesize keys the new API dropped (home-assistant configs are frozen)."""
    result = {}
    for key, value in sensors.items():
        if isinstance(value, bool):
            value = int(value)
        result[key] = value
        legacy = SENSOR_KEY_ALIASES.get(key)
        if legacy:
            result[legacy] = result[key]
    # old climateStatus: 1 while heating or cooling is active; upstream now
    # reports that via the status of the corresponding UI buttons
    climate_active = False
    for b in buttons or []:
        if b.get("activateCommand") in ("heatingOn", "coolingOn") and b.get("status"):
            climate_active = True
    result["climateStatus"] = 1 if climate_active else 0
    # upstream dropped diagnostics entirely, but HA's frozen config renders it
    # as the state of a sensor with unit "km" — a missing/empty value crashes
    # that sensor's state write (non-numeric state), so keep it numeric
    result["diagnostics"] = 0
    return result

def haversine_m(lat1, lon1, lat2, lon2):
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))

# previous GPS fix, used to synthesize speed (lost on restart — first value is 0)
last_position_fix = {}

def build_position_data(sensors, payload):
    position = {}
    for key in ("lat", "lon", "course"):
        if sensors.get(key) is not None:
            position[key] = sensors[key]
    if payload.get("positionAt"):
        position["positionAt"] = payload["positionAt"]
    # upstream no longer reports speed, but HA's GPS automation triggers on
    # it — derive km/h from the distance between consecutive fixes
    global last_position_fix
    speed = 0.0
    try:
        lat = float(sensors["lat"])
        lon = float(sensors["lon"])
        at = payload.get("positionAt")
        prev = last_position_fix
        if at and prev.get("positionAt") and at > prev["positionAt"]:
            dt_s = (at - prev["positionAt"]) / 1000.0
            dist_m = haversine_m(prev["lat"], prev["lon"], lat, lon)
            if dt_s > 0 and dist_m > 1:  # ignore sub-meter GPS jitter while parked
                speed = round(dist_m / dt_s * 3.6, 1)
        if at:
            last_position_fix = {"lat": lat, "lon": lon, "positionAt": at}
    except (KeyError, TypeError, ValueError):
        pass
    position["speed"] = speed
    return position

def fetch_sensor_data(force=False):
    global sensors_data, telemetry_etag
    if not tokens_ok:
        logger.warning("Sensor data fetch skipped: tokens are not active")
        return
    try:
        tokens = get_tokens()
        cookies = {
            "evy-platform-access": tokens["access"],
            "evy-platform-refresh": tokens["refresh"]
        }
        headers = {}
        if telemetry_etag and not force:
            headers["If-None-Match"] = telemetry_etag
        response = upstream.get(EVOLUTE_TELEMETRY_URL, headers=headers, cookies=cookies, timeout=TIMEOUT)
        if response.status_code == 304 and sensors_data:
            # not modified — the cached snapshot is still current
            update_status("last_sensor_update")
            logger.info("Telemetry unchanged (304), keeping cached data")
            return
        response.raise_for_status()
        if response.headers.get("ETag"):
            telemetry_etag = response.headers["ETag"]
        data = response.json()
        for k in JSON_SUB.strip(".").split("."):
            if k:
                data = data.get(k, {})
        sensors = data.get("sensors", {}) if isinstance(data, dict) else {}
        buttons = data.get("buttons", []) if isinstance(data, dict) else []
        sensors_data = {
            "sensorsData": build_sensors_data(sensors, buttons),
            "positionData": build_position_data(sensors, data),
            "meta": {
                "isOnline": data.get("isOnline"),
                "onlineState": data.get("onlineState"),
                "carStateUpdatedAt": data.get("carStateUpdatedAt"),
                "positionAt": data.get("positionAt"),
                "buttons": data.get("buttons", []),
                "warnings": data.get("warnings", []),
            },
        }
        update_status("last_sensor_update")
        write_json_file(DUMP_FILE, sensors_data)
        logger.info("Sensor data updated")
    except Exception as e:
        logger.error(f"Failed to fetch sensor data: {e}")

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
        # NB: abort(jsonify(...), 401) would silently lose the 401 status,
        # werkzeug treats a Response as the whole response
        abort(401, description="Unauthorized")

def check_auth_rw(req):
    key = req.headers.get("X-API-Key") or req.args.get("api_key")
    if key != API_KEY_RW:
        abort(401, description="Unauthorized")

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
        "current_refresh_interval": current_refresh_interval
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
    value = sensors_data.get("sensorsData", {}).get(sensor_name)
    if value is None:
        value = sensors_data.get("positionData", {}).get(sensor_name)
    if value is None:
        return jsonify({"error": "sensor not found"}), 404
    return jsonify({sensor_name: value})

def send_tbox_command(command_name, extra_body=None):
    """POST a command to the new telemetry-commands endpoint, returns parsed JSON."""
    tokens = get_tokens()
    payload = {"commandName": command_name, "imei": CAR_ID}
    if extra_body:
        payload.update(extra_body)
    cookies = {
        "evy-platform-access": tokens["access"],
        "evy-platform-refresh": tokens["refresh"]
    }
    resp = upstream.post(EVOLUTE_COMMANDS_URL, json=payload, cookies=cookies, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()

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

@app.route("/tbox/<string:action>", methods=["POST"])
def tbox_action(action):
    check_auth_rw(request)
    extra_body = {}
    if request.data:
        try:
            body = json.loads(request.get_data())
            if isinstance(body, dict):
                extra_body = body
        except ValueError:
            pass

    try:
        response_data = send_tbox_command(action, extra_body)
        return jsonify({
            "status": "success",
            "commandId": response_data.get("commandId"),
            "response": response_data,
        })
    except Exception as e:
        logger.error(f"TBox action request failed: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/tbox-i/<string:action>", methods=["POST"])
def tbox_i_action(action):
    check_auth_rw(request)

    if action not in INTELLIGENT_ACTIONS:
        return jsonify({"status": "error", "error": f"Unknown intelligent action: {action}"}), 400

    command_name, status_source, skip_when = INTELLIGENT_ACTIONS[action]

    try:
        fetch_sensor_data()

        if status_source is not None:
            kind, key = status_source
            if kind == "sensor":
                current = sensors_data.get("sensorsData", {}).get(key)
                if isinstance(current, str):
                    current = current.lower() in ("1", "true", "on")
                elif current is not None:
                    current = bool(current)
            else:  # button
                current = None
                for b in sensors_data.get("meta", {}).get("buttons", []):
                    if b.get("activateCommand") == key:
                        current = bool(b.get("status"))
                        break

            if current == skip_when:
                logger.info(f"Intelligent action '{action}' skipped: already in desired state")
                return jsonify({"status": "already_ok"})

        response_data = send_tbox_command(command_name)
        logger.info(f"Intelligent action '{action}' sent as command '{command_name}'")
        fetch_sensor_data(force=True)

        return jsonify({
            "status": "success",
            "commandId": response_data.get("commandId"),
        })

    except Exception as e:
        logger.error(f"Intelligent action '{action}' failed: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed"}), 405

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled error: {e}")
    return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    if CAR_ID == "SOME_CAR_IMEI_CHANGE_ME":
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
