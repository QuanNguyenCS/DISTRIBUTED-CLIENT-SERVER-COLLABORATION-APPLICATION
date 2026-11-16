import pytest


@pytest.fixture(autouse=True)
def private_test_room(monkeypatch):
    monkeypatch.setenv("COLLAB_AES_KEY", "Isolated-test-room-secret-2026")
