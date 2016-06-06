from test import TestBase


class TestAlert(TestBase):
    def test_alert_post(self):
        self.burp.alert.post('test alert')
