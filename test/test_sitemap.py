from burp.models.sitemap import Request, Response
from test import TestBase


class TestSiteMap(TestBase):
    def test_sitemap_get_all(self):
        set(self.burp.sitemap.get())

    def test_sitemap_get_unknow_url(self):
        self.burp.sitemap.get('unknow url')

    def test_sitemap(self):
        ret_req, _ = self.burp.sitemap.post(Request(
            host='localhost',
            port=80,
            protocol='http',
            raw=b'',
            comment='test comment',
            highlight='test highlight',
        ), Response(
            raw=b'',
        ))

        set(self.burp.sitemap.get())
