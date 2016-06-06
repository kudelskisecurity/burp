from base64 import b64encode

from typing import Optional, Any, Iterable, Tuple

from burp.models.sitemap import Request, Response, RequestReturned, ResponseReturned, RequestReturned2
from burp.modules import Base, Connector
from burp.utils.json import JsonParser


class SiteMap(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'sitemap')

    def get(self, url: Optional[str] = None) -> Iterable[RequestReturned]:
        if url is None:
            response = self._get((200,))
        else:
            url = b64encode(url.encode()).decode()
            response = self._get((200,), url)

        json = response.json()
        with JsonParser(json):
            return (RequestReturned.from_json(j.pop('request')) for j in json.pop('data'))

    def post(self, request: Request, response: Response) -> Tuple[RequestReturned2, ResponseReturned]:
        ret = self._post((201,), json=dict(
            request=request.to_json(),
            response=response.to_json(),
        ))

        json = ret.json()
        with JsonParser(json):
            return RequestReturned2.from_json(json.pop('request')), \
                   ResponseReturned.from_json(json.pop('response'))
