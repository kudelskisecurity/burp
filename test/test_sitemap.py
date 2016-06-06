from burp.models.sitemap import Request, Response
from test import TestBase


class TestSiteMap(TestBase):
    def test_sitemap_get_all(self):
        set(self.burp.sitemap.get())

    def test_sitemap_get_unknow_url(self):
        self.burp.sitemap.get('unknow url')

    def test_sitemap(self):
        ret_req, _ = self.burp.sitemap.post(Request(
            host=self.target,
            port=80,
            protocol='http',
            raw=b'GET / HTTP/1.1\n',
            comment='test comment',
            highlight='test highlight',
        ), Response(
            raw=b'nothing',
        ))

        set(self.burp.sitemap.get())
