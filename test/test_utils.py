import unittest

from burp.utils.json import JsonParser, ElementStillInJSONError


class TestUtils(unittest.TestCase):
    def test_utils_jsonparser(self):
        json = {'a': 1}

        with JsonParser(json):
            json.pop('a')

    def test_utils_jsonparser_not_empty(self):
        json = {'a': 1}

        jp = JsonParser(json).__enter__()
        self.assertRaises(ElementStillInJSONError, jp.__exit__)

    def test_utils_jsonparser_contained_mapping(self):
        json = {'a': {'b': 1}}

        with JsonParser(json):
            contained = json.pop('a')
            contained.pop('b')

    def test_utils_jsonparser_contained_mapping_not_empty(self):
        json = {'a': {'b': {'c': 1, 'd': {}}}}

        jp = JsonParser(json).__enter__()
        a = json.pop('a')
        b = a.pop('b')
        b.pop('d')
        self.assertRaises(ElementStillInJSONError, jp.__exit__)
