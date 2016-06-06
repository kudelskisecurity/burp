from test import TestBase


class TestSpider(TestBase):
    def setUp(self):
        super().setUp()
        self.test_url = 'http://perdu.com'

    def test_spider_add(self):
        self.burp.spider.post(self.test_url)

    def test_spider_add_invalid(self):
        self.burp.spider.post('http://unknown_url')

    def test_spider_add_twice(self):
        self.burp.spider.post(self.test_url)
        self.burp.spider.post(self.test_url)
