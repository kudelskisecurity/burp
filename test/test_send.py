from burp.modules.send import Request
from burp.models.send import Tool, Request
from test import TestBase


class TestSend(TestBase):
    def test_send_post_intruder(self):
        self.burp.send.post(Tool.INTRUDER,
            Request(
            host='localhost',
            port=80,
            use_https=False,
            request=b'',
        ))

    def test_send_post_repeater(self):
        self.burp.send.post(Tool.REPEATER,
            Request(
            host='localhost',
            port=80,
            use_https=False,
            request=b'',
        ))
