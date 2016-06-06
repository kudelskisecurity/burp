from datetime import datetime

from burp.models import Cookie
from burp.models.scan.active import Scan
from burp.models.scanissues import ScanIssueReturned
from test import TestBase


class TestSerialize(TestBase):
    def test_serialize_scanissuereturned(self):
        json = {
            'url': self.url,
            'host': self.target,
            'port': 4444,
            'protocol': 'http',
            'name': 'Hello World',
            'issueType': 134217728,
            'severity': 'Information',
            'confidence': 'Certain',
            'issueBackground': 'beep',
            'remediationBackground': 'boop',
            'issueDetail': 'foo',
            'remediationDetail': 'bar',
            'requestResponses': [
                {
                    'request': {
                        'host': self.target,
                        'port': 4444,
                        'protocol': 'http',
                        'httpVersion': 'HTTP/1.1',
                        'raw': 'R0VUIC8gSFRUUDEuMQ\u003d\u003d',
                        'inScope': False,
                        'toolFlag': 16962,
                        'referenceID': 0
                    },
                    'response': {
                        'statusCode': 0,
                        'raw': 'SFRUUCAyMDAgT0s\u003d',
                        'host': self.target,
                        'protocol': 'http',
                        'port': 4444,
                        'inScope': False,
                        'toolFlag': 16962,
                        'referenceID': 0
                    }
                },
            ],
            'inScope': False,
        }

        ScanIssueReturned.from_json(json)

    def test_serialize_cookie(self):
        json_ref = {
            'domain': self.target,
            'name': 'SID',
            'value': '192891pj2ijf90u129',
            'expiration': 'Oct 15, 2014 9:09:44 AM'
        }
        date_ref = datetime(2014, 10, 15, 9, 9, 44)

        cookie = Cookie.from_json(json_ref.copy())
        self.assertEqual(cookie.expiration, date_ref)
        # self.assertEqual(cookie.to_json(), json_ref) TODO date format really this important?

    def test_serialize_scanreturned(self):
        json = {
            'id': 1,
            'errors': 0,
            'insertionPointCount': 0,
            'requestCount': 0,
            'status': '0% complete',
            'percentComplete': 0,
            'issues': []
        }

        Scan.from_json(json)
