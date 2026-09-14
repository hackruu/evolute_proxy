"""Обвес тестов evolute_proxy.

Env-переменные задаются ДО импорта evolute_api — модуль читает конфигурацию
на этапе импорта. Autouse-фикстура `isolated` перенаправляет все файловые
артефакты (токены, dump.json, status.json) в tmp_path, чтобы тесты никогда
не трогали реальные файлы в корне репозитория.
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

os.environ["API_KEY"] = "test-ro-key"
os.environ["API_KEY_RW"] = "test-rw-key"
os.environ["CAR_ID"] = "test-car-id"

import pytest

import evolute_api as api


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Чистое состояние модуля и файловая песочница на каждый тест."""
    monkeypatch.setattr(api, "EVOLUTE_TOKEN_FILENAME", str(tmp_path / "access.txt"))
    monkeypatch.setattr(api, "EVOLUTE_REFRESH_TOKEN_FILENAME", str(tmp_path / "refresh.txt"))
    monkeypatch.setattr(api, "DUMP_FILE", str(tmp_path / "dump.json"))
    monkeypatch.setattr(api, "STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(api, "sensors_data", {})
    monkeypatch.setattr(api, "tokens_ok", False)
    monkeypatch.setattr(api, "current_refresh_interval", api.REFRESH_INTERVAL)
    monkeypatch.setitem(api.status_info, "last_token_update", None)
    monkeypatch.setitem(api.status_info, "last_sensor_update", None)
    yield


@pytest.fixture
def client():
    return api.app.test_client()
