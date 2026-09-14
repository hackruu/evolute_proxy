"""Тесты новых read/passthrough эндпоинтов и опциональной SQLite-истории.

Контракты /travels/*, /telemetry-commands* сняты с живого облака EVY
(бандл веб-кабинета app.evassist.ru) и проверены на реальном аккаунте:
  - filters — массив {key, values}: PERIOD=[ALL|TODAY|YESTERDAY|WEEK|MONTH]
    или DATE_START/DATE_END (epoch ms);
  - /travels/details требует ?startTime=<segmentStartTime> (unix-секунды),
    иначе облако отвечает ValidateError;
  - /client-bff-service/telemetry-commands: POST -> {commandId}, GET — статус.
"""

import json
import sqlite3

import pytest
import requests

import evolute_api as api
from fakes import FakeResponse

RO = {"X-API-Key": "test-ro-key"}
RW = {"X-API-Key": "test-rw-key"}

SNAPSHOT = {
    "time": 1_700_000_000,
    "sensorsData": {"batteryPercentage": 53, "odometer": 3672},
    "positionData": {"lat": 45.0, "lon": 41.9, "speed": 0},
}


# --- travels_search_body: чистая сборка body ---

def test_travels_body_empty_uses_defaults():
    body = api.travels_search_body({})
    assert body == {
        "filters": [{"key": "PERIOD", "values": ["ALL"]}],
        "limit": api.TRAVELS_DEFAULT_LIMIT,
        "offset": 0,
        "sort": {"by": "DATE", "dir": "DESC"},
    }


def test_travels_body_none_is_treated_as_empty():
    assert api.travels_search_body(None) == api.travels_search_body({})


def test_travels_body_provided_fields_win():
    filters = [{"key": "DATE_START", "values": [1789300000000]}]
    body = api.travels_search_body(
        {"filters": filters, "limit": 5, "offset": 10, "sort": {"by": "DATE", "dir": "ASC"}}
    )
    assert body["filters"] == filters
    assert body["limit"] == 5
    assert body["offset"] == 10
    assert body["sort"] == {"by": "DATE", "dir": "ASC"}


def test_travels_body_partial_merge():
    body = api.travels_search_body({"limit": 7})
    assert body["limit"] == 7
    assert body["offset"] == 0
    assert body["filters"] == [{"key": "PERIOD", "values": ["ALL"]}]


# --- история: append/get, retention, отключённый режим ---

def test_history_disabled_by_default_makes_no_file(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "HISTORY_DB", "")
    api.append_history(SNAPSHOT)
    assert list(tmp_path.iterdir()) == []


def test_history_append_uses_upstream_time_and_roundtrips(tmp_path, monkeypatch):
    db = str(tmp_path / "hist.sqlite")
    monkeypatch.setattr(api, "HISTORY_DB", db)
    api.append_history(SNAPSHOT)
    rows = api.get_history(0, 2_000_000_000, 100)
    assert len(rows) == 1
    assert rows[0]["time"] == 1_700_000_000
    assert rows[0]["sensorsData"]["batteryPercentage"] == 53


def test_history_append_without_time_falls_back_to_now(tmp_path, monkeypatch):
    db = str(tmp_path / "hist.sqlite")
    monkeypatch.setattr(api, "HISTORY_DB", db)
    api.append_history({"sensorsData": {}})
    rows = api.get_history(0, 2_000_000_000, 100)
    assert len(rows) == 1


def test_history_repeated_append_same_time_is_replace(tmp_path, monkeypatch):
    db = str(tmp_path / "hist.sqlite")
    monkeypatch.setattr(api, "HISTORY_DB", db)
    api.append_history(SNAPSHOT)
    updated = dict(SNAPSHOT, sensorsData={"batteryPercentage": 54})
    api.append_history(updated)
    rows = api.get_history(0, 2_000_000_000, 100)
    assert len(rows) == 1
    assert rows[0]["sensorsData"]["batteryPercentage"] == 54


def test_history_retention_deletes_old_rows(tmp_path, monkeypatch):
    db = str(tmp_path / "hist.sqlite")
    monkeypatch.setattr(api, "HISTORY_DB", db)
    monkeypatch.setattr(api, "HISTORY_RETENTION_DAYS", 7)
    old = dict(SNAPSHOT, time=1_700_000_000 - 30 * 86400)
    api.append_history(old)
    api.append_history(SNAPSHOT)
    rows = api.get_history(0, 2_000_000_000, 100)
    assert [r["time"] for r in rows] == [1_700_000_000]


def test_history_get_filters_by_range_and_limit(tmp_path, monkeypatch):
    db = str(tmp_path / "hist.sqlite")
    monkeypatch.setattr(api, "HISTORY_DB", db)
    for ts in (100, 200, 300):
        api.append_history(dict(SNAPSHOT, time=ts))
    assert [r["time"] for r in api.get_history(150, 250, 100)] == [200]
    assert [r["time"] for r in api.get_history(0, 1000, 2)] == [100, 200]


def test_history_get_on_fresh_db_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "HISTORY_DB", str(tmp_path / "missing.sqlite"))
    assert api.get_history(0, 2_000_000_000, 10) == []


def test_history_append_bad_path_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "HISTORY_DB", str(tmp_path / "no-such-dir" / "h.sqlite"))
    api.append_history(SNAPSHOT)  # только warn в лог, без исключения


# --- upstream_json: passthrough-семантика ---

def test_upstream_json_forwards_method_url_cookies_and_returns_status(
    isolated, monkeypatch
):
    api.save_token(api.EVOLUTE_TOKEN_FILENAME, "acc-1")
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "ref-1")
    captured = {}

    def fake_request(method, url, **kw):
        captured.update(method=method, url=url, **kw)
        return FakeResponse(201, json_body={"ok": True}, headers=[("Content-Type", "application/json")])

    monkeypatch.setattr(api.requests, "request", fake_request)
    resp = api.upstream_json("PUT", "https://x.example/put", json={"a": 1})

    assert captured["method"] == "PUT"
    assert captured["url"] == "https://x.example/put"
    assert captured["json"] == {"a": 1}
    assert captured["cookies"] == {
        "evy-platform-access": "acc-1",
        "evy-platform-refresh": "ref-1",
    }
    assert resp.status_code == 201
    assert resp.get_json() == {"ok": True}


def test_upstream_json_network_error_is_502(isolated, monkeypatch):
    def fail_request(*a, **kw):
        raise requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(api.requests, "request", fail_request)
    resp = api.upstream_json("GET", "https://x.example/")
    assert resp.status_code == 502
    assert resp.get_json() == {"error": "Upstream request failed"}


# --- e2e: /travels/search, /travels/details ---

def test_travels_search_requires_ro_key(client):
    assert client.post("/travels/search").status_code == 401
    assert client.post("/travels/search", headers=RW).status_code == 401


def test_travels_search_empty_body_posts_defaults(client, isolated, monkeypatch):
    captured = {}

    def fake_request(method, url, **kw):
        captured.update(method=method, url=url, json=kw.get("json"))
        return FakeResponse(200, json_body={"rows": [], "total": 0})

    monkeypatch.setattr(api.requests, "request", fake_request)
    r = client.post("/travels/search", headers=RO)

    assert r.status_code == 200
    assert captured["method"] == "POST"
    assert captured["url"] == api.EVOLUTE_TRAVELS_SEARCH_URL
    assert "test-car-id" in captured["url"]
    assert captured["json"]["filters"] == [{"key": "PERIOD", "values": ["ALL"]}]
    assert captured["json"]["sort"] == {"by": "DATE", "dir": "DESC"}
    assert r.get_json() == {"rows": [], "total": 0}


def test_travels_search_passes_client_body_through(client, isolated, monkeypatch):
    captured = {}

    def fake_request(method, url, **kw):
        captured["json"] = kw.get("json")
        return FakeResponse(200, json_body={"rows": []})

    monkeypatch.setattr(api.requests, "request", fake_request)
    body = {"filters": [{"key": "PERIOD", "values": ["MONTH"]}], "limit": 3, "offset": 6}
    client.post("/travels/search", headers=RO, json=body)
    assert captured["json"]["filters"] == body["filters"]
    assert captured["json"]["limit"] == 3
    assert captured["json"]["offset"] == 6


def test_travels_search_upstream_error_passthrough(client, isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "request",
        lambda *a, **kw: FakeResponse(404, json_body={"name": "Not found"}),
    )
    r = client.post("/travels/search", headers=RO)
    assert r.status_code == 404
    assert r.get_json() == {"name": "Not found"}


def test_travels_details_requires_starttime(client):
    r = client.get("/travels/details/294", headers=RO)
    assert r.status_code == 400
    assert "startTime" in r.get_json()["error"]


def test_travels_details_forwards_starttime(client, isolated, monkeypatch):
    captured = {}

    def fake_request(method, url, **kw):
        captured.update(method=method, url=url, params=kw.get("params"))
        return FakeResponse(200, json_body={"points": [{"lat": 45.0, "lon": 41.9}]})

    monkeypatch.setattr(api.requests, "request", fake_request)
    r = client.get("/travels/details/294?startTime=1789397569", headers=RO)

    assert r.status_code == 200
    assert captured["url"] == f"{api.EVOLUTE_TRAVELS_DETAILS_URL}/294"
    assert captured["params"] == {"startTime": "1789397569"}
    assert r.get_json()["points"][0]["lat"] == 45.0


# --- e2e: /telemetry-commands ---

def test_telemetry_command_create_requires_rw_key(client):
    assert client.post("/telemetry-commands", json={}).status_code == 401
    assert client.post("/telemetry-commands", json={}, headers=RO).status_code == 401


def test_telemetry_command_create_passes_raw_body(client, isolated, monkeypatch):
    captured = {}

    def fake_request(method, url, **kw):
        captured.update(method=method, url=url, data=kw.get("data"),
                        headers=kw.get("headers"))
        return FakeResponse(200, json_body={"commandId": "cmd-1"})

    monkeypatch.setattr(api.requests, "request", fake_request)
    r = client.post(
        "/telemetry-commands", headers={**RW, "Content-Type": "application/json"},
        data=json.dumps({"commandName": "blink", "imei": "x", "value": 1}),
    )

    assert r.status_code == 200
    assert captured["url"] == api.EVOLUTE_TELEMETRY_COMMANDS_URL
    assert json.loads(captured["data"]) == {"commandName": "blink", "imei": "x", "value": 1}
    assert captured["headers"]["Content-Type"] == "application/json"
    assert r.get_json() == {"commandId": "cmd-1"}


def test_telemetry_command_status_auth_matrix(client, isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "request",
        lambda *a, **kw: FakeResponse(200, json_body={"status": "done"}),
    )
    assert client.get("/telemetry-commands/cmd-1").status_code == 401
    assert client.get("/telemetry-commands/cmd-1", headers=RW).status_code == 401
    r = client.get("/telemetry-commands/cmd-1", headers=RO)
    assert r.status_code == 200
    assert r.get_json() == {"status": "done"}


# --- e2e: /history/sensors ---

def test_history_sensors_requires_ro_key(client):
    assert client.get("/history/sensors").status_code == 401
    assert client.get("/history/sensors", headers=RW).status_code == 401


def test_history_sensors_disabled_is_400(client):
    r = client.get("/history/sensors", headers=RO)
    assert r.status_code == 400
    assert "HISTORY_DB" in r.get_json()["error"]


def test_history_sensors_roundtrip_after_fetch(client, isolated, tmp_path, monkeypatch):
    db = str(tmp_path / "hist.sqlite")
    monkeypatch.setattr(api, "HISTORY_DB", db)
    api.tokens_ok = True
    api.save_token(api.EVOLUTE_TOKEN_FILENAME, "acc")
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "ref")
    body = {"sensors": SNAPSHOT}
    monkeypatch.setattr(api.requests, "get", lambda *a, **kw: FakeResponse(200, json_body=body))

    api.fetch_sensor_data()

    r = client.get("/history/sensors?from=0&to=2000000000", headers=RO)
    assert r.status_code == 200
    rows = r.get_json()["rows"]
    assert len(rows) == 1
    assert rows[0]["time"] == 1_700_000_000
    assert rows[0]["sensorsData"]["odometer"] == 3672


def test_history_sensors_window_defaults_exclude_other_rows(client, isolated, tmp_path, monkeypatch):
    db = str(tmp_path / "hist.sqlite")
    monkeypatch.setattr(api, "HISTORY_DB", db)
    api.append_history(dict(SNAPSHOT, time=1))  # древняя строка
    r = client.get("/history/sensors", headers=RO)  # окно: последние 24 ч
    assert r.status_code == 200
    assert r.get_json()["rows"] == []


def test_status_reports_history_flag(client, isolated, tmp_path, monkeypatch):
    assert client.get("/status").get_json()["history_enabled"] is False
    monkeypatch.setattr(api, "HISTORY_DB", str(tmp_path / "h.sqlite"))
    assert client.get("/status").get_json()["history_enabled"] is True
