from burp.models import RequestTiny
from burp.models.enums import Tool
from test import TestBase


class TestSend(TestBase):
    def test_send_post_intruder(self):
        self.burp.send.post(Tool.INTRUDER,
                            RequestTiny(
                                host=self.target,
                                port=80,
                                use_https=False,
                                request=b'GET / HTTP/1.1',
                            ))

    def test_send_post_repeater(self):
        self.burp.send.post(Tool.REPEATER,
                            RequestTiny(
                                host=self.target,
                                port=443,
                                use_https=True,
                                request=b'GET / HTTP/1.1',
                            ))
