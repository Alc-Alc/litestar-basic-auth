from typing import Any

from litestar import Litestar, Request, get
from litestar.connection import ASGIConnection
from litestar.datastructures import State
from msgspec import Struct

from litestar_basic_auth import BasicAuth, BasicAuthCredentials


# This can be a dataclass, Pydantic model, msgspec struct or anything
class User(Struct):
    name: str
    password: str


USER = User(name="user", password="pass")


async def retrieve_user_handler(
    creds: BasicAuthCredentials, _: ASGIConnection[Any, Any, Any, Any]
) -> User | None:
    # logic here to retrieve the user instance
    return (
        USER
        if creds.username == USER.name and creds.password == USER.password
        else None
    )


@get()
async def get_user(request: Request[User, BasicAuthCredentials, State]) -> str:
    return request.user.name


basic_auth = BasicAuth[User](
    retrieve_user_handler,
    exclude=["schema"],
)

app = Litestar(
    [get_user],
    on_app_init=[basic_auth.on_app_init],
)
