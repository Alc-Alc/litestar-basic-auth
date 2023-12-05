from dataclasses import dataclass
from typing import Any

from litestar import Litestar, Request, get
from litestar.connection import ASGIConnection
from litestar.datastructures import State

from litestar_basic_auth import BasicAuthConfig, BasicAuthCredentials, BasicAuthPlugin


# This can be a dataclass, Pydantic model, msgspec struct or anything
@dataclass
class User:
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


app = Litestar(
    [get_user],
    plugins=[
        BasicAuthPlugin(BasicAuthConfig(retrieve_user_handler, exclude=["schema"]))
    ],
)
