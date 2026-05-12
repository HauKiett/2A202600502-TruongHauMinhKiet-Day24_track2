# tests/test_api.py
from fastapi.testclient import TestClient

from src.api.main import app


client = TestClient(app)


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_read_raw_patients():
    response = client.get("/api/patients/raw", headers=auth("token-alice"))
    assert response.status_code == 200
    body = response.json()
    assert body["user"] == "alice"
    assert body["count"] == 10
    assert "cccd" in body["records"][0]


def test_ml_engineer_cannot_read_raw_patients():
    response = client.get("/api/patients/raw", headers=auth("token-bob"))
    assert response.status_code == 403


def test_ml_engineer_can_read_anonymized_patients():
    response = client.get("/api/patients/anonymized", headers=auth("token-bob"))
    assert response.status_code == 200
    body = response.json()
    assert body["user"] == "bob"
    assert body["count"] == 10


def test_data_analyst_can_read_aggregated_metrics():
    response = client.get("/api/metrics/aggregated", headers=auth("token-carol"))
    assert response.status_code == 200
    body = response.json()
    assert body["user"] == "carol"
    assert "by_condition" in body


def test_intern_cannot_read_aggregated_metrics():
    response = client.get("/api/metrics/aggregated", headers=auth("token-dave"))
    assert response.status_code == 403


def test_only_admin_can_delete_patient():
    assert client.delete("/api/patients/demo", headers=auth("token-bob")).status_code == 403
    assert client.delete("/api/patients/demo", headers=auth("token-alice")).status_code == 200
