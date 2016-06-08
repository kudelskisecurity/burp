import pickle

from test import TestBase


class TestPickle(TestBase):
    def test_picklable(self):
        pickled = pickle.dumps(self.burp)
        pickle.loads(pickled)
