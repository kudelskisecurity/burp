from base64 import b64encode
from enum import Enum

from typing import NamedTuple, Mapping, Any


class Tool(Enum):
    REPEATER = 'repeater'
    INTRUDER = 'intruder'


class Request(NamedTuple('Request', [('host', str),
                                     ('port', int),
                                     ('use_https', bool),
                                     ('request', bytes)])):
    def to_json(self) -> Mapping[str, Any]:
        return dict(
            host=self.host,
            port=self.port,
            useHttps=self.use_https,
            request=b64encode(self.request).decode(),
        )