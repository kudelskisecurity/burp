import requests

from burp.models.scan.active import Scan


class BurpError(Exception):
    pass


class WeirdBurpResponseError(BurpError):
    def __init__(self, response: requests.Response) -> None:
        super().__init__(response, response.request.method, response.request.url)
        self.response = response


class ScanNotFoundError(BurpError):
    def __init__(self, scan: Scan) -> None:
        super().__init__(scan)
        self.scan = scan
