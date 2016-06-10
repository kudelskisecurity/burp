from base64 import b64encode
from datetime import datetime

from typing import Any, NamedTuple, Tuple, AbstractSet, Mapping
from typing import Union, MutableMapping, Optional

from burp.utils.json import JsonParser, pop_all, ensure_values, ensure


class Request(NamedTuple('Request', [
    ('host', str),
    ('port', int),
    ('protocol', str),
    ('url', str),
    ('path', str),
    ('query', str),
    ('http_version', str),
    ('method', str),
    ('headers', Tuple[Tuple[str, str], ...]),
    ('body', str),
    ('raw', bytes),
    ('in_scope', bool),
    ('highlight', str),
    ('comment', str),
    ('tool_flag', int),

    ('reference_id', int),
])):
    pass


class RequestSmall(NamedTuple('Request', [
    ('host', str),
    ('port', int),
    ('protocol', str),
    ('raw', bytes),
])):
    def to_json(self) -> Mapping[str, Union[str, int, bool]]:
        return dict(
            host=self.host,
            port=self.port,
            protocol=self.protocol,
            request=b64encode(self.raw).decode(),
        )


class RequestTiny(NamedTuple('Request', [
    ('host', str),
    ('port', int),
    ('use_https', bool),
    ('request', bytes),
])):
    def to_json(self) -> Mapping[str, Union[str, int, bool]]:
        return dict(
            host=self.host,
            port=self.port,
            useHttps=self.use_https,
            request=b64encode(self.request).decode(),
        )


class Cookie(NamedTuple('Cookie', [
    ('domain', Optional[str]),
    ('expiration', Optional[datetime]),
    ('name', str),
    ('value', str),
])):
    __date_format = '%b %d, %Y %I:%M:%S %p'

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'Cookie':
        with JsonParser(json):
            expiration_raw = json.pop('expiration', None)
            expiration = None
            if expiration_raw is not None:
                expiration = datetime.strptime(expiration_raw,
                                               cls.__date_format)
            return Cookie(
                expiration=expiration,
                domain=ensure((str, type(None)), json.pop('domain', None)),
                **pop_all(ensure_values(str, json))
            )

    def to_json(self) -> Mapping[str, Any]:
        return dict(
            domain=self.domain,
            expiration=self.expiration.strftime(self.__date_format),
            name=self.name,
            value=self.value,
        )


class Response(NamedTuple('Response', [
    ('host', str),
    ('port', int),
    ('protocol', str),
    ('headers', Tuple[Tuple[str, str], ...]),
    ('cookies', AbstractSet[Cookie]),  # TODO use frozenset
    ('mime_type', str),
    ('body', str),
    ('raw', bytes),
    ('in_scope', bool),
    ('highlight', str),
    ('comment', str),
    ('tool_flag', int),
])):
    pass


class RequestResponse(NamedTuple('RequestResponse', [
    ('request', Request),
    ('response', Response),
])):
    pass
