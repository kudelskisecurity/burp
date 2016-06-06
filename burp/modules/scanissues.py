from base64 import b64encode

from typing import Iterable, Optional

from burp.models.scanissues import ScanIssue, ScanIssueReturned
from burp.modules import Base, Connector
from burp.utils.json import JsonParser


class ScanIssues(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'scanissues')

    def get(self, url: Optional[str] = None) -> Iterable[ScanIssueReturned]:
        path = url and b64encode(url.encode()).decode()
        response = self._get((200,), path)

        json = response.json()
        with JsonParser(json):
            return (ScanIssueReturned.from_json(s) for s in json.pop('data'))

    def post(self, scan_issue: ScanIssue) -> ScanIssueReturned:
        ret = self._post((201,), json=scan_issue.to_json())
        return ScanIssueReturned.from_json(ret.json())
