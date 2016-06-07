from base64 import b64encode

from typing import NamedTuple, Mapping, Any, Tuple, MutableMapping

from burp.models.errors import BurpError
from burp.utils.json import JsonParser, pop_all, translate_keys, ensure_values, ensure


class Request(NamedTuple('Request', [
    ('host', str),
    ('port', int),
    ('use_https', bool),
    ('request', bytes)
])):
    def to_json(self) -> Mapping[str, Any]:
        return dict(
            host=self.host,
            port=self.port,
            useHttps=self.use_https,
            request=b64encode(self.request).decode(),
        )


class Scan(NamedTuple('Scan', [
    ('id', int),
    ('errors', int),
    ('insertion_point_count', int),
    ('request_count', int),
    ('status', str),
    ('percent_complete', int),
    ('issues', Tuple[Any, ...]),  # TODO specify type
])):
    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'Scan':
        with JsonParser(json):
            return Scan(
                status=ensure(str, json.pop('status')),
                # TODO how to parse?
                issues=tuple(json.pop('issues')) and tuple(),
                **pop_all(translate_keys(ensure_values(int, json), {
                    'insertionPointCount': 'insertion_point_count',
                    'requestCount': 'request_count',
                    'percentComplete': 'percent_complete',
                }))
            )


class ScanNotFoundError(BurpError):
    def __init__(self, scan: Scan) -> None:
        super().__init__(scan)
        self.scan = scan
