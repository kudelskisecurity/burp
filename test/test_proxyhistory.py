from burp.models.send import Request
from test import TestBase


class TestProxyHistory(TestBase):
    def test_proxyhistory_get(self):
        set(self.burp.proxyhistory.get())
