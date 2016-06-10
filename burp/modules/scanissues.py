from base64 import b64encode

from typing import Iterable, Optional, Union

from burp.models.scanissues import ScanIssue, ScanIssueReturnedGetNone
from burp.models.scanissues import ScanIssueReturnedGetMulti
from burp.models.scanissues import ScanIssueReturnedPost
from burp.modules import Base, Connector
from burp.utils.json import JsonParser


class ScanIssues(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'scanissues')

    def get(self, url: Optional[str] = None) \
            -> Union[Iterable[ScanIssueReturnedGetNone],
                     Iterable[ScanIssueReturnedGetMulti]]:
        path = url and b64encode(url.encode()).decode()
        response = self._get((200,), path)

        scan_issue_class = ScanIssueReturnedGetNone
        if url is not None:
            scan_issue_class = ScanIssueReturnedGetMulti  # type: ignore

        json = response.json()
        with JsonParser(json):
            return (scan_issue_class.from_json(s) for s in json.pop('data'))

    def post(self, scan_issue: ScanIssue) -> ScanIssueReturnedPost:
        ret = self._post((201,), json=scan_issue.to_json())
        return ScanIssueReturnedPost.from_json(ret.json())
