"""Заглушки ответов апстрим-облака Evolute для мока `requests` в тестах."""

import json
from types import SimpleNamespace

import requests


class FakeRawHeaders:
    def __init__(self, items):
        self._items = [(str(k), str(v)) for k, v in items]

    def items(self):
        return list(self._items)


class FakeResponse:
    """Минимальный клон requests.Response: status_code, json(), raise_for_status(),
    content, raw.headers.items() — ровно то, что читает evolute_api."""

    def __init__(self, status_code=200, json_body=None, content=b"", headers=None):
        self.status_code = status_code
        self._json_body = json_body
        if content:
            self.content = content
        elif json_body is not None:
            self.content = json.dumps(json_body).encode("utf-8")
        else:
            self.content = b""
        self.text = self.content.decode("utf-8", "replace")
        self.raw = SimpleNamespace(headers=FakeRawHeaders(headers or []))
        self.headers = dict(headers or [])

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body in this fake response")
        return self._json_body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                f"{self.status_code} error", response=self
            )
