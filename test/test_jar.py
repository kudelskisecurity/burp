from datetime import datetime, timedelta

from burp.models import Cookie
from test import TestBase


class TestSpider(TestBase):
    def test_jar_list(self):
        self.burp.jar.get()

    @staticmethod
    def __cookie_in(cookie, jar):
        for c in jar:
            if c.domain == cookie.domain and \
                            c.name == cookie.name and \
                            c.value == cookie.value:
                return True
        return False

    def test_spider_add(self):
        cookie = Cookie(
            domain='perdu.com',
            expiration=datetime.now().replace(microsecond=0) + timedelta(1),
            name='test cookie',
            value='nothing really',
        )
        self.burp.jar.post(cookie)
        self.assertTrue(self.__cookie_in(cookie, self.burp.jar.get()))
