from base64 import b64encode
from datetime import datetime

from typing import NamedTuple, Tuple, AbstractSet, Mapping, Union, MutableMapping, Any

from burp.models.enums import IssueType, ScanStatus
from burp.utils.json import JsonParser, pop_all, ensure_values


class Request(NamedTuple('Request', [('host', str),
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


class Cookie(NamedTuple('Cookie', [('domain', str),
                                   ('expiration', datetime),
                                   ('name', str),
                                   ('value', str),
                                   ])):
    __date_format = '%b %d, %Y %I:%M:%S %p'

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'Cookie':
        with JsonParser(json):
            return Cookie(
                expiration=datetime.strptime(json.pop('expiration'), cls.__date_format),
                **pop_all(ensure_values(str, json))
            )

    def to_json(self) -> Mapping[str, Any]:
        return dict(
            domain=self.domain,
            expiration=self.expiration.strftime(self.__date_format),
            name=self.name,
            value=self.value,
        )


class Response(NamedTuple('Response', [('host', str),
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


class RequestResponse(NamedTuple('RequestResponse', [('request', Request),
                                                     ('response', Response),
                                                     ])):
    pass
