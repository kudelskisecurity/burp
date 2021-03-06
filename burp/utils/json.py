import collections
from copy import copy
from types import TracebackType

from typing import List, TypeVar, Dict, Union
from typing import Optional, MutableMapping, Any, Generator, Tuple, Mapping

from burp.models.errors import InvalidHttpVersion

_T = TypeVar('_T')
_QueueType = List[Tuple[Tuple[str, ...], MutableMapping[str, Any]]]  # flake8: noqa


class ElementStillInJSONError(Exception):
    def __init__(self, path: Tuple[str, ...],
                 elem: Mapping[str, Any]) -> None:
        super().__init__(path, elem)


class JsonParser:
    def __init__(self, json: MutableMapping[str, Any]) -> None:
        self.__maps = list(self.__get_maps(json))

    @staticmethod
    def __get_maps(json: MutableMapping[str, Any]) \
            -> Generator[Tuple[Tuple[str, ...], MutableMapping[str, Any]],
                         None,
                         None]:

        queue = [(tuple(), json)]  # type: _QueueType
        while queue:
            path, elem = queue.pop()
            yield path, elem

            for k, v in elem.items():
                if isinstance(v, collections.MutableMapping):
                    queue.append((path + (k,), v))

    def __enter__(self) -> 'JsonParser':
        return self

    def __exit__(self,
                 exc_type: Optional[type] = None,
                 exc_val: Optional[Exception] = None,
                 exc_tb: Optional[TracebackType] = None) -> bool:
        for path, elem in self.__maps:
            if len(elem) is not 0:
                raise ElementStillInJSONError(path, elem)

        return False


def ensure(needed_type: Union[type, Tuple[type, ...]], value: _T) -> _T:
    if isinstance(value, needed_type):
        return value
    raise TypeError('was not already of type {}'.format(needed_type), value)


# TODO would be nice to provide an overloaded version
def ensure_values(needed_type: type,
                  json: MutableMapping[str, Any]
                  ) -> MutableMapping[str, str]:
    for k, v in json.items():
        if not isinstance(v, needed_type):
            msg = 'do not contain only type {}'.format(needed_type)
            raise TypeError(msg, json, k, v)
    return json


def pop_all(json: MutableMapping[str, Any]) -> Dict[str, Any]:
    try:
        return dict(json.items())
    finally:
        json.clear()


def translate_keys(json: MutableMapping[str, str],
                   translation: MutableMapping[str, str],
                   ) -> MutableMapping[str, str]:
    for k in copy(json):
        v = json[k]
        if k in translation:
            del json[k]
            json[translation[k]] = v
    return json


def parse_http_version(value: str) -> Tuple[int, int]:
    try:
        protocol, version = value.split('/')
        if protocol != 'HTTP':
            raise ValueError()
        major, minor = version.split('.')
        return int(major), int(minor)
    except ValueError:
        raise InvalidHttpVersion(value)
