from base64 import b64encode, b64decode

from typing import Any, Mapping, NamedTuple, Tuple, MutableMapping
from typing import Union, Generator, Optional

from burp.models import RequestSmall, Cookie
from burp.models.enums import IssueSeverity, IssueConfidence, IssueType
from burp.utils.json import JsonParser, ensure, parse_http_version, pop_all


class Response(NamedTuple('Response', [
    ('host', str),
    ('port', int),
    ('protocol', str),
    ('raw', bytes),
])):
    def to_json(self) -> Mapping[str, Union[int, str]]:
        return dict(
            host=self.host,
            port=self.port,
            protocol=self.protocol,
            raw=b64encode(self.raw).decode(),
        )


class ScanIssue(NamedTuple('ScanIssue', [
    ('url', str),
    ('host', str),
    ('port', int),
    ('protocol', str),  # TODO maybe enum
    ('name', str),
    ('issue_type', IssueType),
    ('severity', IssueSeverity),
    ('confidence', IssueConfidence),
    ('issue_background', str),
    ('remediation_background', str),
    ('issue_detail', str),
    ('remediation_detail', str),
    ('requests_responses', Tuple[Tuple[RequestSmall, Response], ...]),
])):
    def __new__(cls, host: str, port: int, protocol: str,
                **kwargs: Union[str,
                                IssueType,
                                IssueSeverity,
                                Tuple[Tuple[RequestSmall, Response], ...]]) \
            -> 'ScanIssue':
        url = '{}://{}:{}/'.format(protocol, host, port)
        return super().__new__(cls,
                               url=url,
                               host=host,
                               port=port,
                               protocol=protocol,
                               **kwargs)

    def to_json(self) -> Mapping[str, Any]:
        return dict(
            url=self.url,
            host=self.host,
            port=self.port,
            protocol=self.protocol,
            name=self.name,
            issueType=self.issue_type.value,
            severity=self.severity.value,
            confidence=self.confidence.value,
            issueBackground=self.issue_background,
            remediationBackground=self.remediation_background,
            issueDetail=self.issue_detail,
            remediationDetail=self.remediation_detail,
            requestResponses=[dict(
                request=req.to_json(),
                response=res.to_json()
            ) for req, res in self.requests_responses],
        )


class RequestReturnedGetNone(NamedTuple('RequestReturnedGetNone', [
    ('in_scope', bool),
    ('http_version', Tuple[int, int]),
    ('body', bytes),
    ('tool_flag', int),
    ('url', str),
    ('method', str),
    ('protocol', str),
    ('path', str),
    ('headers', Tuple[Tuple[str, str], ...]),
    ('port', int),
    ('host', str),
    ('raw', bytes),
    ('reference_id', int),
    ('query', Optional[str]),
])):
    @classmethod
    def __pop_headers(cls, json: MutableMapping[str, Any]) \
            -> Generator[Tuple[str, str], None, None]:
        yield from ((ensure(str, k), ensure(str, v))
                    for k, v in pop_all(json.pop('headers')).items())

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) \
            -> 'RequestReturnedGetNone':
        with JsonParser(json):
            assert json.pop('messageType', None) == 'request'
            return RequestReturnedGetNone(
                in_scope=ensure(bool, json.pop('inScope')),
                http_version=parse_http_version(json.pop('httpVersion')),
                body=b64decode(json.pop('body').encode()),
                tool_flag=ensure(int, json.pop('toolFlag')),
                url=ensure(str, json.pop('url')),
                method=ensure(str, json.pop('method')),
                protocol=ensure(str, json.pop('protocol')),
                path=ensure(str, json.pop('path')),
                headers=tuple(cls.__pop_headers(json)),
                port=ensure(int, json.pop('port')),
                host=ensure(str, json.pop('host')),
                raw=b64decode(json.pop('raw').encode()),
                reference_id=ensure(int, json.pop('referenceID')),
                query=ensure((str, type(None)), json.pop('query', None)),
            )


class ResponseReturnedGetNone(NamedTuple('ResponseReturnedGetNone', [
    ('in_scope', bool),
    ('body', bytes),
    ('tool_flag', int),
    ('protocol', str),
    ('headers', Tuple[Tuple[str, str], ...]),
    ('port', int),
    ('host', str),
    ('raw', bytes),
    ('reference_id', int),

    ('mime_type', str),
    ('status_code', int),
    ('cookies', Tuple[Cookie, ...]),
])):
    @classmethod
    def __pop_headers(cls, json: MutableMapping[str, Any]) \
            -> Generator[Tuple[str, str], None, None]:
        yield from ((ensure(str, k), ensure(str, v))
                    for k, v in pop_all(json.pop('headers')).items())

    @classmethod
    def __pop_cookies(cls, json: MutableMapping[str, Any]) \
            -> Generator[Cookie, None, None]:
        yield from (Cookie.from_json(j) for j in json.pop('cookies'))

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) \
            -> 'ResponseReturnedGetNone':
        with JsonParser(json):
            assert json.pop('messageType', None) == 'response'
            return ResponseReturnedGetNone(
                in_scope=ensure(bool, json.pop('inScope')),
                protocol=ensure(str, json.pop('protocol')),
                port=ensure(int, json.pop('port')),
                raw=b64decode(json.pop('raw').encode()),
                body=b64decode(json.pop('body').encode()),
                headers=tuple(cls.__pop_headers(json)),
                cookies=tuple(cls.__pop_cookies(json)),
                mime_type=ensure(str, json.pop('mimeType')),
                host=ensure(str, json.pop('host')),
                tool_flag=ensure(int, json.pop('toolFlag')),
                status_code=ensure(int, json.pop('statusCode')),
                reference_id=ensure(int, json.pop('referenceID')),
            )


class ScanIssueReturnedGetNone(NamedTuple('ScanIssueReturnedGetNone', [
    ('in_scope', bool),
    ('url', str),
    ('protocol', str),
    ('port', int),
    ('host', str),
    ('requests_responses', Tuple[Tuple[RequestReturnedGetNone,
                                       ResponseReturnedGetNone], ...]),
    ('confidence', IssueConfidence),
    ('severity', IssueSeverity),
    ('issue_type', IssueType),
    ('remediation_background', Optional[str]),
    ('remediation_detail', Optional[str]),
    ('issue_background', str),
    ('issue_detail', Optional[str]),
    ('name', str),
])):
    @classmethod
    def __get_response(cls, json: MutableMapping[str, Any]) \
            -> Optional[ResponseReturnedGetNone]:
        try:
            return ResponseReturnedGetNone.from_json(json.pop('response'))
        except KeyError:
            return None

    @classmethod
    def __pop_requests_responses(cls, json: MutableMapping[str, Any]) \
            -> Generator[Tuple[RequestReturnedGetNone,
                               Optional[ResponseReturnedGetNone]],
                         None, None]:
        yield from (
            (
                RequestReturnedGetNone.from_json(elem.pop('request')),
                cls.__get_response(elem),
            ) for elem in json.pop('requestResponses'))

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) \
            -> 'ScanIssueReturnedGetNone':
        with JsonParser(json):
            assert json.pop('messageType', None) == 'scanIssue'
            req_res = tuple(cls.__pop_requests_responses(json))
            remed_back = ensure((str, type(None)),
                                json.pop('remediationBackground', None))
            remed_detail = ensure((str, type(None)),
                                  json.pop('remediationDetail', None))
            issue_detail = ensure((str, type(None)),
                                  json.pop('issueDetail', None))
            return ScanIssueReturnedGetNone(
                protocol=ensure(str, json.pop('protocol')),
                host=ensure(str, json.pop('host')),
                port=ensure(int, json.pop('port')),
                severity=IssueSeverity(json.pop('severity')),
                confidence=IssueConfidence(json.pop('confidence')),
                url=ensure(str, json.pop('url')),
                name=ensure(str, json.pop('name')),
                requests_responses=req_res,
                remediation_background=remed_back,
                remediation_detail=remed_detail,
                issue_background=ensure(str, json.pop('issueBackground')),
                issue_detail=issue_detail,
                in_scope=ensure(bool, json.pop('inScope')),
                issue_type=IssueType(json.pop('issueType')),
            )


class ScanIssueReturnedGetMulti(NamedTuple('ScanIssueReturnedGetMulti', [

])):
    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) \
            -> 'ScanIssueReturnedGetMulti':
        with JsonParser(json):
            return ScanIssueReturnedGetMulti()


class ScanIssueReturnedPost(NamedTuple('ScanIssueReturnedPost', [

])):
    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) \
            -> 'ScanIssueReturnedPost':
        with JsonParser(json):
            return ScanIssueReturnedPost()
