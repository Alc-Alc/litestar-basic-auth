from collections.abc import Awaitable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from litestar.config.app import AppConfig
from litestar.connection import ASGIConnection
from litestar.plugins import InitPluginProtocol
from litestar.types import Method

from . import BasicAuth, BasicAuthCredentials, BasicAuthMiddleware


@dataclass
class BasicAuthConfig:
    retrieve_user_handler: Callable[
        [BasicAuthCredentials, ASGIConnection[Any, Any, Any, Any]], Awaitable[Any]
    ]
    exclude: str | list[str] | None = None
    auth_header: str = "Authorization"
    description: str = "Basic Auth"
    openapi_security_scheme_name: str = "BasicAuth"
    authentication_middleware_class: type[BasicAuthMiddleware] = BasicAuthMiddleware

    exclude_http_methods: Sequence[Method] | None = field(
        default_factory=lambda: ["OPTIONS", "HEAD"]
    )


class BasicAuthPlugin(InitPluginProtocol):
    def __init__(self, config: BasicAuthConfig):
        self.config = config

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        return BasicAuth(**asdict(self.config)).on_app_init(app_config)
