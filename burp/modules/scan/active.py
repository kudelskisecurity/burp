from typing import Iterable, Optional

from burp.modules import Connector
from burp.models.scan.active import Request, Scan, ScanNotFoundError
from burp.modules import WeirdBurpResponseError
from burp.modules.scan import Scan as ScanModule
from burp.utils.json import JsonParser


class ScanActive(ScanModule):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'active')

    def post(self, request: Request) -> None:
        self._post((201,), json=request.to_json())

    def get(self, scan: Optional[Scan] = None) -> Iterable[Scan]:
        try:
            path = None
            if scan is not None:
                path = str(scan.id)
            response = self._get((200,), path)
        except WeirdBurpResponseError as e:
            if e.response.status_code != 404:
                raise
            raise ScanNotFoundError(scan)

        json = response.json()

        if scan is not None:
            return iter([Scan.from_json(json)])
        with JsonParser(json):
            return (Scan.from_json(j) for j in json.pop('data'))

    def delete(self, scan: Scan) -> None:
        try:
            self._delete((204,), str(scan.id))
        except WeirdBurpResponseError as e:
            if e.response.status_code != 404:
                raise
            raise ScanNotFoundError(scan)
