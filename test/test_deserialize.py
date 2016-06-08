import importlib
import json
from datetime import datetime
from pathlib import Path

from burp.models import Cookie
from test import TestBase


class TestSerialize(TestBase):
    def test_deserialize_cookie(self):
        json_ref = {
            'domain': self.target,
            'name': 'SID',
            'value': '192891pj2ijf90u129',
            'expiration': 'Oct 15, 2014 9:09:44 AM'
        }
        date_ref = datetime(2014, 10, 15, 9, 9, 44)

        cookie = Cookie.from_json(json_ref.copy())
        self.assertEqual(cookie.expiration, date_ref)

    @staticmethod
    def __get_mod_class(file):
        class_sub_path = file.name.split('_', maxsplit=1)[0]

        module_name = 'burp.models'
        if ':' in class_sub_path:
            sub_path, class_name = class_sub_path.split(':', maxsplit=1)
            module_name += '.' + sub_path
        else:
            class_name = class_sub_path

        return class_name, module_name

    @staticmethod
    def __get_data_dir():
        test_dir = Path(__file__).parent
        absolute = test_dir / 'data'
        return absolute.relative_to(test_dir)

    def test_deserialize(self):
        data_dir = self.__get_data_dir()
        for file in data_dir.glob('*.json'):
            class_name, module_name = self.__get_mod_class(file)

            module = importlib.import_module(module_name)
            klass = getattr(module, class_name)
            assert klass.__name__ == class_name

            content_json = json.load(file.open())

            with self.subTest(klass=klass, file=str(file)):
                if not isinstance(content_json, list):
                    content_json = [content_json]
                for elem in content_json:
                    klass.from_json(elem)
