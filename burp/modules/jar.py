from typing import Iterable

from burp.models import Cookie
from burp.modules import Base, Connector
from burp.utils.json import JsonParser


class Jar(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'jar')

    def get(self) -> Iterable[Cookie]:
        ret = self._get((200,))
        json = ret.json()

        with JsonParser(json):
            return (Cookie.from_json(j) for j in json.pop('data'))

    def post(self, cookie: Cookie) -> None:
        ret = self._post((201,), json=cookie.to_json())
        json = ret.json()

        with JsonParser(json):
            return Cookie.from_json(json)
