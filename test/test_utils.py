import unittest

from burp.models.errors import InvalidHttpVersion
from burp.utils.json import JsonParser, ElementStillInJSONError, parse_http_version


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

    def test_utils_parse_http_version(self):
        self.assertEqual(parse_http_version('HTTP/1.1'), (1, 1))

    def __assert_invalid_http_version(self, value):
        self.assertRaises(InvalidHttpVersion, parse_http_version, value)

    def test_utils_parse_http_version_missing_slash(self):
        self.__assert_invalid_http_version('HTTP1.1')

    def test_utils_parse_http_version_missing_dot(self):
        self.__assert_invalid_http_version('HTTP/11')

    def test_utils_parse_http_version_unknow_proto(self):
        self.__assert_invalid_http_version('HTTPS/1.1')

    def test_utils_parse_http_version_missing_proto(self):
        self.__assert_invalid_http_version('/1.1')
