from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from litestar.testing import TestClient

from litestar_basic_auth.app import app


def test_basic_auth_no_header() -> None:
    with TestClient(app) as client:
        response = client.get("")
        assert response.status_code == HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Authorization header is missing"


def test_basic_auth_invalid_authorization_header_value() -> None:
    with TestClient(app) as client:
        response = client.get("", headers={"Authorization": "Basic 123"})
        assert response.status_code == HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Credentials decoding error: invalid format"


def test_basic_auth_invalid_authorization_header_format() -> None:
    with TestClient(app) as client:
        response = client.get("", headers={"Authorization": "Basic123"})
        assert response.status_code == HTTP_401_UNAUTHORIZED
        assert (
            response.json()["detail"]
            == "Invalid header format: missing scheme or credentials"
        )


def test_basic_auth_invalid_authorization_header_missing_header() -> None:
    with TestClient(app) as client:
        response = client.get("", headers={"Authorization": "NotBasic 123"})
        assert response.status_code == HTTP_401_UNAUTHORIZED
        assert (
            response.json()["detail"] == "Header does not contain Basic authentication"
        )


def test_basic_auth_invalid_credentials() -> None:
    with TestClient(app) as client:
        response = client.get("", auth=("user", "not pass"))
        assert response.status_code == HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "User authentication failed"


def test_basic_auth_valid_credentials() -> None:
    with TestClient(app) as client:
        response = client.get("", auth=("user", "pass"))
        assert response.status_code == HTTP_200_OK
        assert response.text == "some value"
