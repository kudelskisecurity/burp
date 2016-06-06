from base64 import b64encode

from typing import NamedTuple, Mapping, Any


class RequestResponse(NamedTuple('RequestResponse', [('host', str),
                                                     ('port', int),
                                                     ('use_https', bool),
                                                     ('request', bytes),
                                                     ('response', bytes)])):
    def to_json(self) -> Mapping[str, Any]:
        return dict(
            host=self.host,
            port=self.port,
            useHttps=self.use_https,
            request=b64encode(self.request).decode(),
            response=b64encode(self.response).decode(),
        )
