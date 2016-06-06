from typing import Iterable, Any

from burp.modules import Base, Connector
from burp.models.sitemap import RequestReturned
from burp.utils.json import JsonParser


class ProxyHistory(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'proxyhistory')

    def get(self) -> Iterable[Any]:
        ret = self._get((200,))
        json = ret.json()
        with JsonParser(json):
            for request in json.pop('data'):
                yield RequestReturned.from_json(request.pop('request'))
