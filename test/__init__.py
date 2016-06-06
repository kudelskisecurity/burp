import os
import unittest

from burp import Burp


class TestBase(unittest.TestCase):
    def setUp(self):
        self.burp = Burp(
            os.environ['BURP_HOST'],
            os.environ['BURP_PORT'],
        )
