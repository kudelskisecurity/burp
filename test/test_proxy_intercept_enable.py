from burp.models.send import Request
from test import TestBase


class TestProxyInterceptEnable(TestBase):
    def test_proxy_intercept_enable_post(self):
        self.burp.proxy.intercept.enable.post()
