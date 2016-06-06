import os
import unittest

from burp import Burp


class TestBase(unittest.TestCase):
    def setUp(self):
        host, port = os.environ['BURP_HOST'], os.environ['BURP_PORT']
        self.burp = Burp(host, port)

        self.proxy = 'http://{}:{}'.format(host, port)
        self.target = os.environ['BURP_TARGET']
        self.url = 'http://' + self.target
