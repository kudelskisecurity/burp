from burp.models.scan.passive import RequestResponse
from test import TestBase


class TestScanPassive(TestBase):
    def test_scan_passive_post(self):
        self.skipTest('raise NPE, see burpbuddy#22')
        self.burp.scan.passive.post(RequestResponse(
            host='localhost',
            port=80,
            use_https=False,
            request=b'',
            response=b'',
        ))
