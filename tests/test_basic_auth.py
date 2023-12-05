from collections.abc import Iterable

import pytest
from litestar import Litestar
from litestar.status_codes import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from litestar.testing import TestClient

from litestar_basic_auth.app import app, USER
from litestar_basic_auth.app_with_plugin import app as app_with_plugin

LitestarTestClient = TestClient[Litestar]

@pytest.fixture(params=[app, app_with_plugin])
def client(request: pytest.FixtureRequest) -> Iterable[LitestarTestClient]:
    with TestClient(request.param) as client:
        yield client


def test_basic_auth_no_header(client: LitestarTestClient) -> None:
    with TestClient(app) as client:
        response = client.get("")
        assert response.status_code == HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Authorization header is missing"


def test_basic_auth_invalid_authorization_header_value(client: LitestarTestClient) -> None:
    response = client.get("", headers={"Authorization": "Basic 123"})
    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Credentials decoding error: invalid format"


def test_basic_auth_invalid_authorization_header_format(client: LitestarTestClient) -> None:
    response = client.get("", headers={"Authorization": "Basic123"})
    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert (
        response.json()["detail"]
        == "Invalid header format: missing scheme or credentials"
    )


def test_basic_auth_invalid_authorization_header_missing_header(client: LitestarTestClient) -> None:
    response = client.get("", headers={"Authorization": "NotBasic 123"})
    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert (
        response.json()["detail"] == "Header does not contain Basic authentication"
    )


def test_basic_auth_invalid_credentials(client: LitestarTestClient) -> None:
    response = client.get("", auth=("user", "not pass"))
    assert response.status_code == HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "User authentication failed"


def test_basic_auth_valid_credentials(client: LitestarTestClient) -> None:
    response = client.get("", auth=("user", "pass"))
    assert response.status_code == HTTP_200_OK
    assert response.text == USER.name
