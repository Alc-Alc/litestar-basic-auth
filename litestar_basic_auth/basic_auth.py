from base64 import b64decode
from binascii import Error
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Generic


from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.middleware import (
    AbstractAuthenticationMiddleware,
    AuthenticationResult,
    DefineMiddleware,
)
from litestar.openapi.spec import Components, SecurityRequirement, SecurityScheme
from litestar.security.base import AbstractSecurityConfig, UserType
from litestar.types import ASGIApp, Method, Scopes


@dataclass
class BasicAuthCredentials:
    username: str
    password: str


class BasicAuthMiddleware(AbstractAuthenticationMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        auth_header: str,
        exclude: str | list[str] | None,
        exclude_http_methods: Sequence[Method] | None,
        exclude_opt_key: str,
        retrieve_user_handler: Callable[
            [BasicAuthCredentials, ASGIConnection[Any, Any, Any, Any]], Awaitable[Any]
        ],
        scopes: Scopes,
    ) -> None:
        super().__init__(
            app=app,
            exclude=exclude,
            exclude_from_auth_key=exclude_opt_key,
            exclude_http_methods=exclude_http_methods,
            scopes=scopes,
        )
        self.auth_header = auth_header
        self.retrieve_user_handler = retrieve_user_handler

    async def authenticate_request(
        self, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationResult:
        header = connection.headers.get(self.auth_header)

        if not header:
            raise NotAuthorizedException("Authorization header is missing")

        basic_auth_creds = self.extract_basic_auth(header)
        retrieved_user = await self.retrieve_user_handler(basic_auth_creds, connection)

        if not retrieved_user:
            raise NotAuthorizedException("User authentication failed")

        return AuthenticationResult(user=retrieved_user, auth=basic_auth_creds)

    def extract_basic_auth(self, header: str) -> BasicAuthCredentials:
        # Adopted from https://github.com/miguelgrinberg/Flask-HTTPAuth/blob/52a13b15be17fb058dac160f8c4d460593b6ddce/src/flask_httpauth.py
        try:
            scheme, credentials = header.encode().split(b" ", 1)
        except ValueError:
            raise NotAuthorizedException(
                "Invalid header format: missing scheme or credentials"
            )

        if scheme == b"Basic":
            try:
                encoded_username, encoded_password = b64decode(credentials).split(
                    b":", 1
                )
            except Error:
                raise NotAuthorizedException(
                    "Credentials decoding error: invalid format"
                )

            try:
                username = encoded_username.decode("utf-8")
                password = encoded_password.decode("utf-8")
            except UnicodeDecodeError:
                username = encoded_username.decode("latin1")
                password = encoded_password.decode("latin1")

            return BasicAuthCredentials(username, password)

        raise NotAuthorizedException("Header does not contain Basic authentication")


@dataclass
class BasicAuth(
    Generic[UserType], AbstractSecurityConfig[UserType, BasicAuthCredentials]
):
    retrieve_user_handler: Callable[
        [BasicAuthCredentials, ASGIConnection[Any, Any, Any, Any]], Awaitable[Any]
    ]
    exclude: str | list[str] | None = None
    auth_header: str = "Authorization"
    description: str = "Basic Auth"
    openapi_security_scheme_name: str = "BasicAuth"
    authentication_middleware_class: type[AbstractAuthenticationMiddleware] = field(
        default=BasicAuthMiddleware
    )
    exclude_http_methods: Sequence[Method] | None = field(
        default_factory=lambda: ["OPTIONS", "HEAD"]
    )

    @property
    def middleware(self) -> DefineMiddleware:
        return DefineMiddleware(
            self.authentication_middleware_class,
            exclude=self.exclude,
            exclude_opt_key=self.exclude_opt_key,
            exclude_http_methods=self.exclude_http_methods,
            retrieve_user_handler=self.retrieve_user_handler,
            scopes=self.scopes,
            auth_header=self.auth_header,
        )

    @property
    def openapi_components(self) -> Components:
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="http",
                    scheme="Basic",
                    name=self.auth_header,
                    description=self.description,
                )
            }
        )

    @property
    def security_requirement(self) -> SecurityRequirement:
        return {self.openapi_security_scheme_name: []}
