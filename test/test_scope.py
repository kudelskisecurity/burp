from test import TestBase


class TestScope(TestBase):
    def setUp(self):
        super().setUp()
        self.test_url = 'http://perdu.com'

    def test_scope_post(self):
        self.burp.scope.post(self.test_url)

    def test_scope_is_in(self):
        self.burp.scope.post(self.test_url)
        self.assertTrue(self.burp.scope.get(self.test_url))

    def test_scope_is_in_not_existing(self):
        self.assertFalse(self.burp.scope.get('http://unknown_url'))

    def test_scope_delete(self):
        self.burp.scope.post(self.test_url)
        self.burp.scope.delete(self.test_url)

    def test_scope_delete_not_existing(self):
        self.burp.scope.delete('http://unknown_url')
