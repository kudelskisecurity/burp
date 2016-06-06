import requests


class BurpError(Exception):
    pass


class WeirdBurpResponseError(BurpError):
    def __init__(self, response: requests.Response) -> None:
        super().__init__(response, response.request.method, response.request.url, response.text)
        self.response = response


class InvalidHttpVersion(Exception):
    def __init__(self, http_version: str) -> None:
        super().__init__('unable to parse received httpVersion', http_version)
