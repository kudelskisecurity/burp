from burp.models.enums import IssueType, IssueConfidence, IssueSeverity
from burp.models.scanissues import ScanIssue
from test import TestBase


class TestScanIssues(TestBase):
    def test_scanissues_list(self):
        self.burp.scanissues.get()

    def test_scanissues_get_empty(self):
        self.assertSetEqual(set(self.burp.scanissues.get('nothing found at this address')), frozenset())

    def test_scanissues_add(self):
        scanissue = ScanIssue(
            host='perdu.com',
            port=80,
            protocol='http',
            name='test scanissues add',
            issue_type=IssueType.CLIENT_SIDE_SQL_INJECTION_DOM_BASED,
            severity=IssueSeverity.HIGH,
            confidence=IssueConfidence.CERTAIN,
            issue_background='dsa',
            remediation_background='boop',
            issue_detail='foo',
            remediation_detail='bar',
            requests_responses=tuple(),
        )
        self.burp.scanissues.post(scanissue)

        scanissue_ret = next(self.burp.scanissues.get('http://perdu.com'))

        self.assertEqual(scanissue.url, scanissue_ret.url)
        self.assertEqual(scanissue.host, scanissue_ret.host)
        self.assertEqual(scanissue.port, scanissue_ret.port)
        self.assertEqual(scanissue.protocol, scanissue_ret.protocol)
        self.assertEqual(scanissue.name, scanissue_ret.name)
        # self.assertEqual(scanissue.issue_type, scanissue_ret.issue_type) see burpbuddy#23
        self.assertEqual(scanissue.confidence, scanissue_ret.confidence)
        self.assertEqual(scanissue.remediation_background, scanissue_ret.remediation_background)
        self.assertEqual(scanissue.issue_detail, scanissue_ret.issue_detail)
        self.assertEqual(scanissue.remediation_detail, scanissue_ret.remediation_detail)
        self.assertEqual(len(scanissue.requests_responses), len(scanissue_ret.requests_responses))
