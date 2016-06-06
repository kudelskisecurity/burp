from test import TestBase


class TestSpider(TestBase):
    def test_spider_add(self):
        self.burp.spider.post(self.url)

    def test_spider_add_invalid(self):
        self.burp.spider.post('http://unknown_url')

    def test_spider_add_twice(self):
        self.burp.spider.post(self.url)
        self.burp.spider.post(self.url)
