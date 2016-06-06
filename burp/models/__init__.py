from typing import NamedTuple, Tuple, AbstractSet, Generator

from burp.models.enums import IssueType, ScanStatus
from burp.models.jar import Cookie


def to_raw(host: str, path: str, headers: Tuple[Tuple[str, str], ...] = tuple(),
           body: str = '', method: str = 'GET', http_version: Tuple[int, int] = (1, 1)) -> bytes:
    def _get_raw() -> Generator[str, None, None]:
        version = 'HTTP/{}.{}'.format(http_version[0], http_version[1])  # TODO mypy#1553
        yield '{} {} {}'.format(method, path, version)
        yield 'Host: {}'.format(host)
        for k, v in headers:
            yield '{}: {}'.format(k, v)
        yield ''
        yield body

    return b''.join((s + '\n').encode() for s in _get_raw())


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


class ScanIssue(NamedTuple('ScanIssue', [('host', str),
                                         ('port', int),
                                         ('protocol', str),  # TODO maybe enum
                                         ('name', str),
                                         ('issue_type', IssueType),
                                         ('confidence', str),  # TODO maybe enum
                                         ('issue_background', str),
                                         ('remediation_background', str),
                                         ('issue_detail', str),
                                         ('remediation_detail', str),
                                         ('requests_responses', Tuple[Tuple[Request, Response], ...]),
                                         ('in_scope', bool),
                                         ])):
    pass


class RequestResponse(NamedTuple('RequestResponse', [('request', Request),
                                                     ('response', Response),
                                                     ])):
    pass


class InvalidHttpVersion(Exception):
    def __init__(self, http_version: str) -> None:
        super().__init__('unable to parse received httpVersion', http_version)