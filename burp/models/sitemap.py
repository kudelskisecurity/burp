from base64 import b64encode, b64decode
from itertools import chain

from typing import NamedTuple, Mapping, Any, MutableMapping, Union, Tuple

from burp.models import InvalidHttpVersion
from burp.utils.json import ensure, JsonParser, pop_all, ensure_values


class Request(NamedTuple('Request', [('host', str),
                                     ('port', int),
                                     ('protocol', str),
                                     ('raw', bytes),
                                     ('comment', str),
                                     ('highlight', str)])):  # TODO potential enum

    def to_json(self) -> Mapping[str, Any]:
        return dict(
            host=self.host,
            port=self.port,
            protocol=self.protocol,
            raw=b64encode(self.raw).decode(),
            comment=self.comment,
            highlight=self.highlight,
        )


class Response(NamedTuple('Response', [('raw', bytes)])):
    def to_json(self) -> Mapping[str, Any]:
        return dict(
            raw=b64encode(self.raw).decode(),
        )


_COMMON_RETURNED_FIELDS = [
    ('in_scope', bool),
    ('tool_flag', int),  # TODO potential flag
    ('reference_id', int),
]


def _common_returned(json: MutableMapping[str, Any]) -> Mapping[str, Union[bytes, bool, int]]:
    return dict(
        port=ensure(int, json.pop('port')),
        raw=b64decode(json.pop('raw')).decode(),
        in_scope=ensure(bool, json.pop('inScope')),
        tool_flag=ensure(int, json.pop('toolFlag')),
        reference_id=ensure(int, json.pop('referenceID')),
    )


class RequestReturned(NamedTuple('RequestReturned',
                                 _COMMON_RETURNED_FIELDS +
                                 [('url', str),
                                  ('host', str),
                                  ('port', int),
                                  ('protocol', str),
                                  ('raw', bytes),
                                  ('http_version', Tuple[int, int]),
                                  ('method', str),
                                  ('body', bytes),
                                  ('path', str),
                                  ('headers', Tuple[Tuple[str, str], ...])])):
    @staticmethod
    def __parse_http_version(value: str) -> Tuple[int, int]:
        try:
            protocol, version = value.split('/')
            if protocol != 'HTTP':
                raise ValueError()
            major, minor = version.split('.')
            return int(major), int(minor)
        except ValueError:
            raise InvalidHttpVersion(value)

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'RequestReturned':
        with JsonParser(json):
            json.pop('messageType')
            return RequestReturned(
                http_version=cls.__parse_http_version(json.pop('httpVersion')),
                headers=tuple((ensure(str, k), ensure(str, v)) for k, v in pop_all(json.pop('headers')).items()),
                body=b64decode(json.pop('body').encode()),
                **dict(chain(
                    _common_returned(json).items(),
                    pop_all(ensure_values(str, json)).items(),
                ))
            )


class RequestReturned2(NamedTuple('RequestReturned',
                                  _COMMON_RETURNED_FIELDS +
                                  [('host', str),
                                   ('port', int),
                                   ('protocol', str),
                                   ('raw', bytes),
                                   ('http_version', Tuple[int, int]),
                                   ('highlight', str),
                                   ('comment', str)])):
    @staticmethod
    def __parse_http_version(value: str) -> Tuple[int, int]:
        try:
            protocol, version = value.split('/')
            if protocol != 'HTTP':
                raise ValueError()
            major, minor = version.split('.')
            return int(major), int(minor)
        except ValueError:
            raise InvalidHttpVersion(value)

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'RequestReturned':
        with JsonParser(json):
            return RequestReturned2(
                http_version=cls.__parse_http_version(json.pop('httpVersion')),
                # headers=tuple((ensure(str, k), ensure(str, v)) for k, v in pop_all(json.pop('headers')).items()),
                # body=b64decode(json.pop('body').encode()),
                **dict(chain(
                    _common_returned(json).items(),
                    pop_all(ensure_values(str, json)).items(),
                ))
            )


class ResponseReturned(NamedTuple('ResponseReturned',
                                  list(Response._field_types.items()) +
                                  _COMMON_RETURNED_FIELDS +
                                  [('status_code', int),  # TODO potential enum
                                   ('port', int)])):
    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'ResponseReturned':
        with JsonParser(json):
            return ResponseReturned(
                status_code=ensure(int, json.pop('statusCode')),
                **_common_returned(json)
            )
