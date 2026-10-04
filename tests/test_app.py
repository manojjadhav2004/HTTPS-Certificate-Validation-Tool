"""Flask dashboard API tests (uses the local lab)."""
import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_dashboard_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"HTTPS Certificate Validator" in response.data


def test_static_files_are_served(client):
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_api_valid_certificate(client, lab_servers):
    response = client.post("/api/validate", json={"target": "localhost", "port": "4443", "use_lab_ca": True})
    data = response.get_json()
    assert response.status_code == 200
    assert data["verdict"] == "SECURE"
    assert len(data["checks"]) == 7


def test_api_expired_certificate(client, lab_servers):
    data = client.post("/api/validate", json={"target": "localhost", "port": 4445, "use_lab_ca": True}).get_json()
    assert data["verdict"] == "NOT SECURE"


def test_api_without_lab_ca_is_untrusted(client, lab_servers):
    data = client.post("/api/validate", json={"target": "localhost", "port": 4443}).get_json()
    assert data["verdict"] == "NOT SECURE"


def test_api_invalid_input(client):
    response = client.post("/api/validate", json={"target": "http://example.com"})
    assert response.status_code == 400
    assert response.get_json()["error"]["kind"] == "invalid_input"


def test_api_rejects_non_json(client):
    assert client.post("/api/validate", data="nope").status_code == 400


def test_api_connection_refused(client):
    data = client.post("/api/validate", json={"target": "localhost", "port": 1}).get_json()
    assert data["error"]["kind"] in ("refused", "timeout", "network")
    assert data["verdict"] is None
