from test import TestBase


class TestProxyInterceptDisable(TestBase):
    def test_proxy_intercept_disable_post(self):
        self.burp.proxy.intercept.disable.post()
