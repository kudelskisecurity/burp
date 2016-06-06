from test import TestBase


class TestState(TestBase):
    def test_state_get(self):
        self.burp.state.get()

    def test_state(self):
        self.burp.state.post(self.burp.state.get())
