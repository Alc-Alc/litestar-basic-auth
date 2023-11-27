from typing import Any
from pydantic import BaseModel, EmailStr

from litestar import Litestar, get
from litestar.connection import ASGIConnection

from litestar_basic_auth.basic_auth import BasicAuth, BasicAuthCredentials


class User(BaseModel):
    name: str
    password: str
    email: EmailStr


USER = User(name="user", password="pass", email="user@pass.com")


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
async def something() -> str:
    return "some value"


basic_auth = BasicAuth[User](
    retrieve_user_handler,
    exclude=["schema"],
)

app = Litestar(
    [something],
    on_app_init=[basic_auth.on_app_init],
)
