from base64 import b64encode

from burp.modules import Base, Connector
from burp.utils.json import JsonParser


class Scope(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'scope')

    def get(self, url: str) -> bool:
        encoded_url = b64encode(url.encode()).decode()

        response = self._get((200, 404), encoded_url)

        return response.status_code == 200

    def post(self, url: str) -> str:
        ret = self._post((201,), json=dict(
            url=url
        ))

        json = ret.json()
        with JsonParser(json):
            return json.pop('url')

    def delete(self, url: str) -> None:
        encoded_url = b64encode(url.encode()).decode()
        self._delete((204,), encoded_url)
