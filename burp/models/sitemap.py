from base64 import b64encode, b64decode
from itertools import chain

from typing import NamedTuple, Mapping, Any, MutableMapping, Tuple, Dict

from burp.utils.json import ensure, JsonParser, pop_all, ensure_values, parse_http_version


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


def _common_returned(json: MutableMapping[str, Any]) -> Dict[str, Any]:
    return dict(
        port=ensure(int, json.pop('port')),
        raw=b64decode(json.pop('raw').encode()),
        in_scope=ensure(bool, json.pop('inScope')),
        tool_flag=ensure(int, json.pop('toolFlag')),
        reference_id=ensure(int, json.pop('referenceID')),
    )


class RequestReturned(NamedTuple('RequestReturned',
                                 [('url', str),
                                  ('host', str),
                                  ('port', int),
                                  ('protocol', str),
                                  ('raw', bytes),
                                  ('http_version', Tuple[int, int]),
                                  ('method', str),
                                  ('body', bytes),
                                  ('path', str),
                                  ('headers', Tuple[Tuple[str, str], ...]),
                                  ('in_scope', bool),
                                  ('tool_flag', int),  # TODO potential flag
                                  ('reference_id', int)])):
    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'RequestReturned':
        with JsonParser(json):
            json.pop('messageType')
            json.pop('query', None)  # TODO sometimes it's there
            json.pop('comment', None)  # TODO sometimes it's there
            return RequestReturned(
                http_version=parse_http_version(json.pop('httpVersion')),
                headers=tuple((ensure(str, k), ensure(str, v)) for k, v in pop_all(json.pop('headers')).items()),
                body=b64decode(json.pop('body').encode()),
                **dict(chain(
                    _common_returned(json).items(),
                    pop_all(ensure_values(str, json)).items(),
                ))
            )


class RequestReturned2(NamedTuple('RequestReturned',
                                  [('host', str),
                                   ('port', int),
                                   ('protocol', str),
                                   ('raw', bytes),
                                   ('http_version', Tuple[int, int]),
                                   ('highlight', str),
                                   ('comment', str),
                                   ('in_scope', bool),
                                   ('tool_flag', int),  # TODO potential flag
                                   ('reference_id', int)])):
    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'RequestReturned2':
        with JsonParser(json):
            return RequestReturned2(
                http_version=parse_http_version(json.pop('httpVersion')),
                # headers=tuple((ensure(str, k), ensure(str, v)) for k, v in pop_all(json.pop('headers')).items()),
                # body=b64decode(json.pop('body').encode()),
                **dict(chain(
                    _common_returned(json).items(),
                    pop_all(ensure_values(str, json)).items(),
                ))
            )


class ResponseReturned(NamedTuple('ResponseReturned',
                                  [('status_code', int),  # TODO potential enum
                                   ('port', int),
                                   ('raw', bytes),
                                   ('in_scope', bool),
                                   ('tool_flag', int),  # TODO potential flag
                                   ('reference_id', int)])):
    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'ResponseReturned':
        with JsonParser(json):
            return ResponseReturned(
                status_code=ensure(int, json.pop('statusCode')),
                **dict(_common_returned(json).items())
            )
