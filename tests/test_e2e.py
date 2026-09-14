"""E2E-тесты: полный цикл запрос→ответ через Flask test client.

Апстрим-облако Evolute замокано на границе `requests`; проверяются ровно те
контракты, которые видит реальный клиент прокси: auth-матрица, роутинг,
passthrough-семантика /proxy, обработка ошибок.
"""

import pytest
import requests

import evolute_api as api
from fakes import FakeResponse

RO = {"X-API-Key": "test-ro-key"}
RW = {"X-API-Key": "test-rw-key"}


# --- liveness / status ---

def test_ping_no_auth(client):
    r = client.get("/ping")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_status_reports_liveness_and_flags(client, isolated):
    r = client.get("/status")
    body = r.get_json()
    assert r.status_code == 200
    assert body["alive"] is True
    assert body["uptime"] >= 0
    assert body["tokens_active"] is False
    assert body["current_refresh_interval"] == api.REFRESH_INTERVAL
    api.tokens_ok = True
    assert client.get("/status").get_json()["tokens_active"] is True


# --- /set_tokens ---

def test_set_tokens_requires_auth(client):
    assert client.post("/set_tokens", json={"access": "x"}).status_code == 401


def test_set_tokens_saves_and_resets_interval(client, isolated):
    api.current_refresh_interval = 3600  # был backoff
    r = client.post("/set_tokens", headers=RO, json={"access": "acc-1", "refresh": "ref-1"})
    assert r.status_code == 200
    assert api.load_token(api.EVOLUTE_TOKEN_FILENAME) == "acc-1"
    assert api.load_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME) == "ref-1"
    assert api.current_refresh_interval == api.REFRESH_INTERVAL


def test_set_tokens_partial_update_keeps_other_token(client, isolated):
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "keep-me")
    r = client.post("/set_tokens", headers=RO, json={"access": "only-access"})
    assert r.status_code == 200
    assert api.load_token(api.EVOLUTE_TOKEN_FILENAME) == "only-access"
    assert api.load_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME) == "keep-me"


def test_set_tokens_auth_via_query_param(client, isolated):
    r = client.post("/set_tokens?api_key=test-ro-key", json={"access": "q"})
    assert r.status_code == 200
    assert api.load_token(api.EVOLUTE_TOKEN_FILENAME) == "q"


# --- /manual_refresh ---

def test_manual_refresh_success(client, isolated, monkeypatch):
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "r-old")

    def fake_post(url, **kw):
        assert url == api.EVOLUTE_REFRESH_URL
        return FakeResponse(200, json_body={"accessToken": "a-new", "refreshToken": "r-new"})

    monkeypatch.setattr(api.requests, "post", fake_post)
    r = client.post("/manual_refresh", headers=RO)
    assert r.status_code == 200
    assert r.get_json() == {"status": "refreshed", "interval": api.REFRESH_INTERVAL}
    assert api.tokens_ok is True
    assert api.load_token(api.EVOLUTE_TOKEN_FILENAME) == "a-new"


def test_manual_refresh_still_200_on_upstream_403_and_backs_off(client, isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(403, json_body={})
    )
    r = client.post("/manual_refresh", headers=RO)
    assert r.status_code == 200
    assert r.get_json()["interval"] == api.REFRESH_INTERVAL * 2
    assert api.tokens_ok is False


# --- /sensors/all, /position/all ---

def test_sensors_all_requires_ro_key(client, isolated):
    assert client.get("/sensors/all").status_code == 401
    assert client.get("/sensors/all", headers=RW).status_code == 401


def test_sensors_all_payload(client, isolated):
    api.sensors_data = {"sensorsData": {"externalTemperature": 20}}
    r = client.get("/sensors/all", headers=RO)
    assert r.status_code == 200
    assert r.get_json() == {"externalTemperature": 20}


def test_sensors_all_404_without_data(client, isolated):
    r = client.get("/sensors/all", headers=RO)
    assert r.status_code == 404
    assert r.get_json() == {"error": "No sensors data available"}


def test_position_all_payload_and_404(client, isolated):
    assert client.get("/position/all", headers=RO).status_code == 404
    api.sensors_data = {"positionData": {"latitude": 55.75, "longitude": 37.61}}
    r = client.get("/position/all", headers=RO)
    assert r.status_code == 200
    assert r.get_json()["latitude"] == 55.75


# --- /sensors/<name> ---

def test_single_sensor_requires_rw_key_current_behavior(client, isolated):
    # NB: сейчас одиночный сенсор требует RW-ключ, хотя /sensors/all — RO-ключ.
    # Тест фиксирует текущее поведение; если это баг — править вместе с тестом.
    api.sensors_data = {"externalTemperature": 21}
    assert client.get("/sensors/externalTemperature", headers=RO).status_code == 401
    r = client.get("/sensors/externalTemperature", headers=RW)
    assert r.status_code == 200
    assert r.get_json() == {"externalTemperature": 21}


def test_single_sensor_unknown_404(client, isolated):
    r = client.get("/sensors/nope", headers=RW)
    assert r.status_code == 404
    assert r.get_json() == {"error": "sensor not found"}


# --- /proxy/<path>: passthrough ---

def test_proxy_get_passthrough(client, isolated, monkeypatch):
    api.save_token(api.EVOLUTE_TOKEN_FILENAME, "acc-p")
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "ref-p")
    captured = {}

    def fake_request(method, url, headers=None, params=None, data=None,
                     cookies=None, timeout=None, allow_redirects=None):
        captured.update(method=method, url=url, headers=headers or {}, data=data,
                        cookies=cookies, allow_redirects=allow_redirects)
        return FakeResponse(200, json_body={"ok": True},
                            headers=[("Content-Type", "application/json"),
                                     ("X-Upstream", "yes"), ("Content-Encoding", "gzip"),
                                     ("Connection", "close")])

    monkeypatch.setattr(api.requests, "request", fake_request)
    r = client.get("/proxy/car-service/tbox/xxx/info",
                   headers={**RW, "X-Track": "t1", "User-Agent": "evolute-proxy-tests/1.0"})

    assert r.status_code == 200
    assert r.get_json() == {"ok": True}
    assert captured["method"] == "GET"
    assert captured["url"] == "https://app.evassist.ru/car-service/tbox/xxx/info"
    sent = {k.lower(): v for k, v in captured["headers"].items()}
    assert sent["x-track"] == "t1"
    assert sent["user-agent"] == "evolute-proxy-tests/1.0"  # UA клиента пробрасывается
    assert "x-api-key" not in sent
    assert "host" not in sent
    assert captured["cookies"] == {"evy-platform-access": "acc-p", "evy-platform-refresh": "ref-p"}
    assert captured["allow_redirects"] is False
    # hop-by-hop заголовки апстрима не протекают клиенту
    assert r.headers.get("Content-Type") == "application/json"
    assert r.headers.get("X-Upstream") == "yes"
    assert "Content-Encoding" not in r.headers
    assert "Connection" not in r.headers


def test_proxy_post_body_and_content_type(client, isolated, monkeypatch):
    captured = {}

    def fake_request(method, url, headers=None, data=None, **kw):
        captured.update(headers=headers or {}, data=data)
        return FakeResponse(201, content=b'{"created": true}')

    monkeypatch.setattr(api.requests, "request", fake_request)
    r = client.post("/proxy/car-service/command", headers=RW,
                    data=b'{"cmd": 1}', content_type="application/json")

    assert r.status_code == 201
    assert r.data == b'{"created": true}'
    sent = {k.lower(): v for k, v in captured["headers"].items()}
    assert sent["content-type"] == "application/json"
    assert captured["data"] == b'{"cmd": 1}'


def test_proxy_relays_upstream_error_status(client, isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "request",
        lambda *a, **kw: FakeResponse(418, content=b"teapot"),
    )
    r = client.get("/proxy/whatever", headers=RW)
    assert r.status_code == 418
    assert r.data == b"teapot"


def test_proxy_upstream_failure_returns_500_json(client, isolated, monkeypatch):
    def boom(*a, **kw):
        raise requests.exceptions.ConnectTimeout("down")

    monkeypatch.setattr(api.requests, "request", boom)
    r = client.get("/proxy/whatever", headers=RW)
    assert r.status_code == 500
    assert r.get_json() == {"error": "Proxy failed"}


def test_proxy_requires_rw_key(client, isolated):
    assert client.get("/proxy/x").status_code == 401
    assert client.get("/proxy/x", headers=RO).status_code == 401


# --- /tbox/<action> ---

def test_tbox_action_happy_path(client, isolated, monkeypatch):
    captured = {}

    def fake_post(url, headers=None, data=None, **kw):
        captured.update(url=url, data=data)
        return FakeResponse(200, json_body={"result": "accepted"})

    monkeypatch.setattr(api.requests, "post", fake_post)
    r = client.post("/tbox/centralLockingToggle", headers=RW, data=b'{"cmd": 1}')

    assert r.status_code == 200
    assert r.get_json() == {"status": "success"}
    assert captured["url"] == f"https://app.evassist.ru/car-service/tbox/{api.CAR_ID}/centralLockingToggle"
    assert captured["data"] == b'{"cmd": 1}'


def test_tbox_action_auth_matrix(client, isolated):
    assert client.post("/tbox/blink").status_code == 401
    assert client.post("/tbox/blink", headers=RO).status_code == 401


def test_tbox_action_upstream_error_maps_to_500(client, isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "post", lambda *a, **kw: FakeResponse(403, json_body={})
    )
    r = client.post("/tbox/blink", headers=RW)
    assert r.status_code == 500
    body = r.get_json()
    assert body["status"] == "error"
    assert "403" in body["error"]


# --- /tbox-i/<action>: интеллектуальные действия ---

def test_tbox_i_unknown_action_400(client, isolated):
    r = client.post("/tbox-i/moonwalk", headers=RW)
    assert r.status_code == 400
    assert "Unknown intelligent action" in r.get_json()["error"]


def test_tbox_i_skips_when_already_in_desired_state(client, isolated, monkeypatch):
    api.sensors_data = {"sensorsData": {"climateStatus": 1}}

    def fail_post(*a, **kw):
        raise AssertionError("upstream tbox must not be called")

    monkeypatch.setattr(api.requests, "post", fail_post)
    r = client.post("/tbox-i/heating_on", headers=RW)
    assert r.status_code == 200
    assert r.get_json() == {"status": "already_ok"}


def test_tbox_i_executes_when_state_differs(client, isolated, monkeypatch):
    # tokens_ok=False: внутренний рефetch сенсоров пропускается, состояние из кэша
    api.tokens_ok = False
    api.sensors_data = {"sensorsData": {"climateStatus": 0}}
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        return FakeResponse(200, json_body={})

    monkeypatch.setattr(api.requests, "post", fake_post)
    r = client.post("/tbox-i/heating_on", headers=RW)

    assert r.status_code == 200
    assert r.get_json() == {"status": "success"}
    assert captured["url"] == f"https://app.evassist.ru/car-service/tbox/{api.CAR_ID}/heating"


def test_tbox_i_uses_fresh_sensor_state_when_tokens_ok(client, isolated, monkeypatch):
    api.tokens_ok = True
    api.save_token(api.EVOLUTE_TOKEN_FILENAME, "a")
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "r")
    # кэш устарел (0), свежий апстрим вернёт 1 → действие пропускается
    api.sensors_data = {"sensorsData": {"climateStatus": 0}}
    sensor_body = {"sensors": {"sensorsData": {"climateStatus": 1}}}

    monkeypatch.setattr(
        api.requests, "get", lambda *a, **kw: FakeResponse(200, json_body=sensor_body)
    )

    def fail_post(*a, **kw):
        raise AssertionError("upstream tbox must not be called")

    monkeypatch.setattr(api.requests, "post", fail_post)
    r = client.post("/tbox-i/heating_on", headers=RW)
    assert r.get_json() == {"status": "already_ok"}


def test_tbox_i_upstream_failure_500(client, isolated, monkeypatch):
    api.tokens_ok = False
    api.sensors_data = {"sensorsData": {"climateStatus": 0}}
    monkeypatch.setattr(
        api.requests, "post", lambda *a, **kw: FakeResponse(500, json_body={})
    )
    r = client.post("/tbox-i/heating_on", headers=RW)
    assert r.status_code == 500
    assert r.get_json()["status"] == "error"


# --- обработка ошибок роутинга ---

def test_unknown_route_json_404(client):
    r = client.get("/definitely-not-here")
    assert r.status_code == 404
    assert r.get_json() == {"error": "Not found"}


def test_wrong_method_json_405(client):
    r = client.get("/set_tokens", headers=RO)
    assert r.status_code == 405
    assert r.get_json() == {"error": "Method Not Allowed"}


# --- auth-матрица по всем защищённым эндпоинтам ---

@pytest.mark.parametrize("path,method,allowed", [
    ("/sensors/all", "get", "ro"),
    ("/position/all", "get", "ro"),
    ("/set_tokens", "post", "ro"),
    ("/manual_refresh", "post", "ro"),
    ("/sensors/externalTemperature", "get", "rw"),
    ("/proxy/car-service/x", "get", "rw"),
    ("/tbox/blink", "post", "rw"),
    ("/tbox-i/blink", "post", "rw"),
])
def test_auth_matrix(client, isolated, monkeypatch, path, method, allowed):
    # страховка: никакой запрос не уходит в реальное облако
    monkeypatch.setattr(
        api.requests, "request", lambda *a, **kw: FakeResponse(200, json_body={})
    )
    monkeypatch.setattr(
        api.requests, "post", lambda *a, **kw: FakeResponse(200, json_body={})
    )
    monkeypatch.setattr(
        api.requests, "get", lambda *a, **kw: FakeResponse(200, json_body={})
    )

    no_key = getattr(client, method)(path)
    ro = getattr(client, method)(path, headers=RO)
    rw = getattr(client, method)(path, headers=RW)

    assert no_key.status_code == 401, path
    if allowed == "ro":
        assert rw.status_code == 401, path
        assert ro.status_code != 401, path
    else:
        assert ro.status_code == 401, path
        assert rw.status_code != 401, path


# --- /proxy: методы записи, query, редиректы, тела ошибок ---

@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_proxy_write_methods_passthrough(client, isolated, monkeypatch, method):
    captured = {}

    def fake_request(m, url, **kw):
        captured["method"] = m
        return FakeResponse(204)

    monkeypatch.setattr(api.requests, "request", fake_request)
    r = getattr(client, method)("/proxy/car-service/x", headers=RW)
    assert r.status_code == 204
    assert captured["method"] == method.upper()


def test_proxy_forwards_query_params(client, isolated, monkeypatch):
    captured = {}

    def fake_request(method, url, params=None, **kw):
        captured["url"] = url
        captured["params"] = params
        return FakeResponse(200, json_body={})

    monkeypatch.setattr(api.requests, "request", fake_request)
    r = client.get("/proxy/car-service/list?page=2&size=10", headers=RW)
    assert r.status_code == 200
    assert captured["url"] == "https://app.evassist.ru/car-service/list"
    assert dict(captured["params"].items()) == {"page": "2", "size": "10"}


def test_proxy_relays_redirect_without_following(client, isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "request",
        lambda *a, **kw: FakeResponse(302, headers=[("Location", "https://app.evassist.ru/login")]),
    )
    r = client.get("/proxy/x", headers=RW)
    assert r.status_code == 302
    assert r.headers.get("Location") == "https://app.evassist.ru/login"


def test_proxy_get_has_no_content_type_upstream(client, isolated, monkeypatch):
    captured = {}

    def fake_request(method, url, headers=None, **kw):
        captured["headers"] = headers or {}
        return FakeResponse(200, json_body={})

    monkeypatch.setattr(api.requests, "request", fake_request)
    client.get("/proxy/x", headers=RW)
    assert "content-type" not in {k.lower() for k in captured["headers"]}


def test_proxy_relays_upstream_500_body(client, isolated, monkeypatch):
    monkeypatch.setattr(
        api.requests, "request",
        lambda *a, **kw: FakeResponse(500, json_body={"upstream": "boom"},
                                      headers=[("Content-Type", "application/json")]),
    )
    r = client.get("/proxy/x", headers=RW)
    assert r.status_code == 500
    assert r.get_json() == {"upstream": "boom"}


# --- /tbox: дополнительные контракты ---

def test_tbox_query_params_not_forwarded(client, isolated, monkeypatch):
    # NB: query-параметры клиента сейчас НЕ пробрасываются в облако.
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        captured["kw"] = kw
        return FakeResponse(200, json_body={})

    monkeypatch.setattr(api.requests, "post", fake_post)
    r = client.post("/tbox/blink?trace=1", headers=RW)
    assert r.status_code == 200
    assert "?" not in captured["url"]
    assert not captured["kw"].get("params")


def test_tbox_forwards_arbitrary_action_name(client, isolated, monkeypatch):
    # /tbox/<action> — прозрачный: имя действия не валидируется на прокси
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(200, json_body={})
    )
    r = client.post("/tbox/whateverAction", headers=RW)
    assert r.status_code == 200
    assert r.get_json() == {"status": "success"}


def test_tbox_empty_body_forwarded(client, isolated, monkeypatch):
    captured = {}

    def fake_post(url, data=None, **kw):
        captured["data"] = data
        return FakeResponse(200, json_body={})

    monkeypatch.setattr(api.requests, "post", fake_post)
    client.post("/tbox/blink", headers=RW)
    assert captured["data"] == b""


# --- /tbox-i: остальные пары действий ---

def test_tbox_i_blink_executes_and_skips(client, isolated, monkeypatch):
    api.tokens_ok = False
    api.sensors_data = {"sensorsData": {"ready": 0}}
    captured = {}

    def fake_post(url, **kw):
        captured["url"] = url
        return FakeResponse(200, json_body={})

    monkeypatch.setattr(api.requests, "post", fake_post)
    r = client.post("/tbox-i/blink", headers=RW)
    assert r.get_json() == {"status": "success"}
    assert captured["url"].endswith(f"/tbox/{api.CAR_ID}/blink")

    api.sensors_data = {"sensorsData": {"ready": 1}}
    r = client.post("/tbox-i/blink", headers=RW)
    assert r.get_json() == {"status": "already_ok"}


def test_tbox_i_prepare_pair(client, isolated, monkeypatch):
    api.tokens_ok = False
    api.sensors_data = {"sensorsData": {"ignitionStatus": 1}}

    def fail_post(*a, **kw):
        raise AssertionError("upstream tbox must not be called")

    monkeypatch.setattr(api.requests, "post", fail_post)
    r = client.post("/tbox-i/prepare_on", headers=RW)
    assert r.get_json() == {"status": "already_ok"}

    api.sensors_data = {"sensorsData": {"ignitionStatus": 0}}
    monkeypatch.setattr(
        api.requests, "post", lambda url, **kw: FakeResponse(200, json_body={})
    )
    r = client.post("/tbox-i/prepare_on", headers=RW)
    assert r.get_json() == {"status": "success"}
    r = client.post("/tbox-i/prepare_off", headers=RW)
    assert r.get_json() == {"status": "already_ok"}


# --- прочие контракты ---

def test_sensors_all_returns_nested_payload_as_is(client, isolated):
    payload = {"sensorsData": {"climateStatus": 0, "nested": {"x": [1, 2]}}}
    api.sensors_data = payload
    r = client.get("/sensors/all", headers=RO)
    assert r.get_json() == payload["sensorsData"]


def test_auth_header_name_case_insensitive(client, isolated):
    api.sensors_data = {"sensorsData": {"externalTemperature": 1}}
    r = client.get("/sensors/all", headers={"x-api-key": "test-ro-key"})
    assert r.status_code == 200


def test_set_tokens_invalid_json_400(client, isolated):
    r = client.post("/set_tokens", headers=RO, data="not json", content_type="application/json")
    assert r.status_code == 400


def test_manual_refresh_network_error_still_200(client, isolated, monkeypatch):
    def boom(url, **kw):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(api.requests, "post", boom)
    r = client.post("/manual_refresh", headers=RO)
    assert r.status_code == 200
    assert r.get_json()["interval"] == api.REFRESH_INTERVAL
    assert api.tokens_ok is False


def test_status_reflects_manual_refresh(client, isolated, monkeypatch):
    api.save_token(api.EVOLUTE_REFRESH_TOKEN_FILENAME, "r")
    monkeypatch.setattr(
        api.requests, "post",
        lambda url, **kw: FakeResponse(200, json_body={"accessToken": "a2", "refreshToken": "r2"}),
    )
    client.post("/manual_refresh", headers=RO)
    body = client.get("/status").get_json()
    assert body["tokens_active"] is True
    assert body["last_token_update"] is not None
