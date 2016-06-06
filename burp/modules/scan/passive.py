from burp import Connector
from burp.models.scan.passive import RequestResponse
from burp.modules.scan import Scan as ScanModule


class ScanPassive(ScanModule):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'passive')

    def post(self, request: RequestResponse) -> None:
        self._post((201,), json=request.to_json())
