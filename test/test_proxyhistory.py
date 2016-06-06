import requests

from test import TestBase


class TestProxyHistory(TestBase):
    def test_proxyhistory_get(self):
        requests.get(self.url, proxies=dict(http=self.proxy))
        set(self.burp.proxyhistory.get())
