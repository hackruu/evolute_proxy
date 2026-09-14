"""Unit-тесты: чистые функции и фоновая логика evolute_api (без HTTP-слоя)."""

import json
from pathlib import Path

import pytest
import requests
from werkzeug.exceptions import Unauthorized

import evolute_api as api
from fakes import FakeResponse


# --- токены: файловый IO ---

def test_save_and_load_token_roundtrip(tmp_path):
    path = tmp_path / "tok.txt"
    api.save_token(str(path), "  tok-123\n")
    assert api.load_token(str(path)) == "tok-123"


def test_load_token_missing_file_returns_empty(tmp_path):
    assert api.load_token(str(tmp_path / "nope.txt")) == ""


def test_get_tokens_reads_both_files(isolated):
    api.save_token(api.EVOLUTE_TOKEN_FILENAME, "acc")
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "ref")
    assert api.get_tokens() == {"access": "acc", "refresh": "ref"}


# --- json: файловый IO ---

def test_read_json_file_valid(tmp_path):
    p = tmp_path / "d.json"
    p.write_text('{"a": 1}', encoding="utf-8")
    assert api.read_json_file(str(p)) == {"a": 1}


def test_read_json_file_broken_returns_default(tmp_path):
    p = tmp_path / "d.json"
    p.write_text("{not json", encoding="utf-8")
    assert api.read_json_file(str(p)) == {}
    assert api.read_json_file(str(p), default={"x": 9}) == {"x": 9}


def test_read_json_file_missing(tmp_path):
    assert api.read_json_file(str(tmp_path / "nope.json"), default=[]) == []


def test_write_json_file_roundtrip(tmp_path):
    p = tmp_path / "out.json"
    api.write_json_file(str(p), {"b": [1, 2]})
    assert json.loads(p.read_text(encoding="utf-8")) == {"b": [1, 2]}


def test_write_json_file_bad_path_does_not_raise(tmp_path):
    api.write_json_file(str(tmp_path / "no-such-dir" / "out.json"), {"a": 1})


# --- refresh_tokens: ротация и backoff ---

def test_refresh_tokens_success_rotates_files(isolated, monkeypatch):
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "old-refresh")
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        captured["payload"] = kw.get("json")
        return FakeResponse(200, json_body={"accessToken": "new-acc", "refreshToken": "new-ref"})

    monkeypatch.setattr(api.requests, "post", fake_post)
    api.refresh_tokens()

    assert captured["url"] == api.EVOLUTE_REFRESH_URL
    assert captured["payload"] == {"refreshToken": "old-refresh"}
    assert api.load_token(api.EVOLUTE_TOKEN_FILENAME) == "new-acc"
    assert api.load_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME) == "new-ref"
    assert api.tokens_ok is True
    assert api.current_refresh_interval == api.REFRESH_INTERVAL


def test_refresh_tokens_success_resets_backoff(isolated, monkeypatch):
    api.current_refresh_interval = 1200  # ранее был 403-backoff
    monkeypatch.setattr(
        api.requests, "post",
        lambda url, **kw: FakeResponse(200, json_body={"accessToken": "a", "refreshToken": "r"}),
    )
    api.refresh_tokens()
    assert api.current_refresh_interval == api.REFRESH_INTERVAL


def test_refresh_tokens_403_doubles_interval(isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(403, json_body={})
    )
    api.refresh_tokens()
    assert api.tokens_ok is False
    assert api.current_refresh_interval == api.REFRESH_INTERVAL * 2


def test_refresh_tokens_403_interval_capped_at_3600(isolated, monkeypatch):
    api.current_refresh_interval = 3000
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(403, json_body={})
    )
    api.refresh_tokens()
    assert api.current_refresh_interval == 3600


def test_refresh_tokens_other_http_error_keeps_interval(isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(500, json_body={})
    )
    api.refresh_tokens()
    assert api.tokens_ok is False
    assert api.current_refresh_interval == api.REFRESH_INTERVAL


def test_refresh_tokens_network_error(isolated, monkeypatch):
    def boom(url, **kw):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(api.requests, "post", boom)
    api.refresh_tokens()
    assert api.tokens_ok is False
    assert api.load_token(api.EVOLUTE_TOKEN_FILENAME) == ""


# --- fetch_sensor_data: поллинг сенсоров ---

def test_fetch_skipped_without_tokens(isolated, monkeypatch):
    def fail_get(*a, **kw):
        raise AssertionError("requests.get must not be called")

    monkeypatch.setattr(api.requests, "get", fail_get)
    api.fetch_sensor_data()
    assert api.sensors_data == {}


def test_fetch_success_extracts_json_sub_path(isolated, monkeypatch):
    api.tokens_ok = True
    api.save_token(api.EVOLUTE_TOKEN_FILENAME, "acc-1")
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "ref-1")
    body = {"sensors": {"sensorsData": {"externalTemperature": 21}, "positionData": {}}}
    captured = {}

    def fake_get(url, headers=None, cookies=None, timeout=None):
        captured.update(url=url, headers=headers, cookies=cookies)
        return FakeResponse(200, json_body=body)

    monkeypatch.setattr(api.requests, "get", fake_get)
    api.fetch_sensor_data()

    assert api.sensors_data == body["sensors"]
    assert captured["url"] == api.EVOLUTE_SENSOR_URL
    assert "test-car-id" in captured["url"]
    assert captured["cookies"]["evy-platform-access"] == "acc-1"
    assert captured["cookies"]["evy-platform-refresh"] == "ref-1"
    assert captured["headers"]["User-Agent"] == api.USER_AGENT
    assert json.loads(Path(api.DUMP_FILE).read_text(encoding="utf-8")) == body["sensors"]


def test_fetch_custom_json_sub_path(isolated, monkeypatch):
    monkeypatch.setattr(api, "JSON_SUB", "payload.sensors")
    api.tokens_ok = True
    body = {"payload": {"sensors": {"sensorsData": {}}}}

    monkeypatch.setattr(
        api.requests, "get",
        lambda *a, **kw: FakeResponse(200, json_body=body),
    )
    api.fetch_sensor_data()
    assert api.sensors_data == {"sensorsData": {}}


def test_fetch_failure_keeps_previous_data(isolated, monkeypatch):
    api.tokens_ok = True
    api.sensors_data = {"sentinel": True}

    def boom(*a, **kw):
        raise requests.exceptions.Timeout("slow")

    monkeypatch.setattr(api.requests, "get", boom)
    api.fetch_sensor_data()
    assert api.sensors_data == {"sentinel": True}


# --- check_auth / check_auth_rw ---

def test_check_auth_header_ok():
    with api.app.test_request_context("/", headers={"X-API-Key": "test-ro-key"}):
        api.check_auth(api.request)


def test_check_auth_query_param_ok():
    with api.app.test_request_context("/?api_key=test-ro-key"):
        api.check_auth(api.request)


def test_check_auth_rejects_rw_key():
    with api.app.test_request_context("/", headers={"X-API-Key": "test-rw-key"}):
        with pytest.raises(Unauthorized):
            api.check_auth(api.request)


def test_check_auth_rejects_missing_key():
    with api.app.test_request_context("/"):
        with pytest.raises(Unauthorized):
            api.check_auth(api.request)


def test_check_auth_rw_accepts_only_rw_key():
    with api.app.test_request_context("/", headers={"X-API-Key": "test-rw-key"}):
        api.check_auth_rw(api.request)
    with api.app.test_request_context("/", headers={"X-API-Key": "test-ro-key"}):
        with pytest.raises(Unauthorized):
            api.check_auth_rw(api.request)


# --- INTELLIGENT_ACTIONS: контракт маппинга ---

def test_intelligent_actions_shape():
    for name, (endpoint, status_key, skip_value) in api.INTELLIGENT_ACTIONS.items():
        assert endpoint, name
        assert status_key, name
        assert skip_value in (0, 1), name


def test_intelligent_actions_specific_mappings():
    assert api.INTELLIGENT_ACTIONS["lock_close"] == ("centralLockingToggle", "centralLockingStatus", 1)
    assert api.INTELLIGENT_ACTIONS["lock_open"] == ("centralLockingToggle", "centralLockingStatus", 0)
    assert api.INTELLIGENT_ACTIONS["heating_on"] == ("heating", "climateStatus", 1)
    assert api.INTELLIGENT_ACTIONS["prepare_on"] == ("PREPARE", "ignitionStatus", 1)
    assert api.INTELLIGENT_ACTIONS["prepare_off"] == ("CANCEL", "ignitionStatus", 0)


def test_intelligent_action_on_off_pairs_are_symmetric():
    # skip-значение = «уже в желаемом состоянии»; его полярность зависит от
    # семантики upstream (замок: 1=закрыт, багажник: 1=открыт, климат: 1=вкл).
    # Инвариант пары: та же команда, тот же status-ключ, значения {0, 1}.
    pairs = [("lock_close", "lock_open"), ("heating_off", "heating_on"),
             ("cooling_off", "cooling_on"), ("trunk_close", "trunk_open")]
    for off_name, on_name in pairs:
        off = api.INTELLIGENT_ACTIONS[off_name]
        on = api.INTELLIGENT_ACTIONS[on_name]
        assert off[0] == on[0], off_name
        assert off[1] == on[1], off_name
        assert {off[2], on[2]} == {0, 1}, off_name


def test_intelligent_action_prepare_pair_is_command_based():
    # PREPARE/CANCEL — разные команды (не тоггл): тот же status-ключ, разные эндпоинты
    on = api.INTELLIGENT_ACTIONS["prepare_on"]
    off = api.INTELLIGENT_ACTIONS["prepare_off"]
    assert on[0] == "PREPARE" and off[0] == "CANCEL"
    assert on[1] == off[1] == "ignitionStatus"
    assert on[2] == 1 and off[2] == 0


# --- backoff: детальная динамика интервала ---

def test_refresh_403_backoff_doubles_repeatedly(isolated, monkeypatch):
    monkeypatch.setattr(api, "REFRESH_INTERVAL", 10)
    api.current_refresh_interval = 10
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(403, json_body={})
    )
    api.refresh_tokens()
    api.refresh_tokens()
    assert api.current_refresh_interval == 40


def test_refresh_403_backoff_cap_reached(isolated, monkeypatch):
    api.current_refresh_interval = 3600
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(403, json_body={})
    )
    api.refresh_tokens()
    assert api.current_refresh_interval == 3600


# --- status-файл и таймстампы ---

def test_update_status_persists_status_json(isolated):
    api.update_status("last_token_update")
    assert api.status_info["last_token_update"] is not None
    saved = json.loads(Path(api.STATUS_FILE).read_text(encoding="utf-8"))
    assert saved["last_token_update"] == api.status_info["last_token_update"]


def test_refresh_success_updates_status_timestamp(isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "post",
        lambda url, **kw: FakeResponse(200, json_body={"accessToken": "a", "refreshToken": "r"}),
    )
    assert api.status_info["last_token_update"] is None
    api.refresh_tokens()
    assert api.status_info["last_token_update"] is not None


def test_fetch_success_updates_sensor_timestamp(isolated, monkeypatch):
    api.tokens_ok = True
    monkeypatch.setattr(
        api.requests, "get", lambda *a, **kw: FakeResponse(200, json_body={"sensors": {}})
    )
    api.fetch_sensor_data()
    assert api.status_info["last_sensor_update"] is not None


def test_write_json_file_is_pretty_printed(tmp_path):
    p = tmp_path / "out.json"
    api.write_json_file(str(p), {"a": 1})
    assert "\n" in p.read_text(encoding="utf-8")


def test_read_json_file_no_default_returns_empty_dict(tmp_path):
    assert api.read_json_file(str(tmp_path / "nope.json")) == {}


# --- токены: краевые случаи ---

def test_get_tokens_missing_files_both_empty(isolated):
    assert api.get_tokens() == {"access": "", "refresh": ""}


def test_load_token_whitespace_only_file(tmp_path):
    p = tmp_path / "w.txt"
    p.write_text("   \n", encoding="utf-8")
    assert api.load_token(str(p)) == ""


def test_user_agent_is_browser_spoof():
    assert api.USER_AGENT.startswith("Mozilla/5.0")
    assert "Chrome/" in api.USER_AGENT


# --- JSON_SUB: глубокие пути ---

def test_fetch_json_sub_three_levels(isolated, monkeypatch):
    monkeypatch.setattr(api, "JSON_SUB", "a.b.c")
    api.tokens_ok = True
    body = {"a": {"b": {"c": {"sensorsData": 1}}}}
    monkeypatch.setattr(
        api.requests, "get", lambda *a, **kw: FakeResponse(200, json_body=body)
    )
    api.fetch_sensor_data()
    assert api.sensors_data == {"sensorsData": 1}


def test_fetch_json_sub_missing_key_yields_empty(isolated, monkeypatch):
    api.tokens_ok = True
    monkeypatch.setattr(
        api.requests, "get", lambda *a, **kw: FakeResponse(200, json_body={})
    )
    api.fetch_sensor_data()
    assert api.sensors_data == {}


# --- аутентификация: краевые случаи ---

def test_check_auth_rejects_empty_key():
    with api.app.test_request_context("/", headers={"X-API-Key": ""}):
        with pytest.raises(Unauthorized):
            api.check_auth(api.request)


# --- фоновые планировщики: контракт таймеров ---

class FakeTimer:
    def __init__(self, interval, fn):
        self.interval = interval
        self.fn = fn
        self.daemon = False

    def start(self):
        pass


def test_periodic_refresh_schedules_with_current_interval(isolated, monkeypatch):
    created = {}

    def fake_timer(interval, fn):
        created["interval"] = interval
        created["fn"] = fn
        return FakeTimer(interval, fn)

    monkeypatch.setattr(api.threading, "Timer", fake_timer)
    monkeypatch.setattr(
        api.requests, "post",
        lambda url, **kw: FakeResponse(200, json_body={"accessToken": "a", "refreshToken": "r"}),
    )
    api.periodic_refresh()
    assert created["interval"] == api.REFRESH_INTERVAL
    assert created["fn"] is api.periodic_refresh


def test_periodic_refresh_schedules_with_backed_off_interval(isolated, monkeypatch):
    api.current_refresh_interval = 1200  # ранее backoff
    created = {}

    def fake_timer(interval, fn):
        created["interval"] = interval
        return FakeTimer(interval, fn)

    monkeypatch.setattr(api.threading, "Timer", fake_timer)
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(403, json_body={})
    )
    api.periodic_refresh()
    assert created["interval"] == 2400


def test_periodic_fetch_schedules_with_sensors_interval(isolated, monkeypatch):
    created = {}

    def fake_timer(interval, fn):
        created["interval"] = interval
        created["fn"] = fn
        return FakeTimer(interval, fn)

    monkeypatch.setattr(api.threading, "Timer", fake_timer)
    api.periodic_fetch()
    assert created["interval"] == api.SENSORS_REFRESH_INTERVAL
    assert created["fn"] is api.periodic_fetch
