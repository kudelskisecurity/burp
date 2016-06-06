from datetime import datetime

from typing import NamedTuple, MutableMapping, Any, Mapping

from burp.utils.json import JsonParser, pop_all, ensure_values


class Cookie(NamedTuple('Cookie', [('domain', str),
                                   ('expiration', datetime),
                                   ('name', str),
                                   ('value', str),
                                   ])):
    __date_format = '%b %d, %Y %I:%M:%S %p'

    @classmethod
    def from_json(cls, json: MutableMapping[str, Any]) -> 'Cookie':
        with JsonParser(json):
            return Cookie(
                expiration=datetime.strptime(json.pop('expiration'), cls.__date_format),
                **pop_all(ensure_values(str, json))
            )

    def to_json(self) -> Mapping[str, Any]:
        return dict(
            domain=self.domain,
            expiration=self.expiration.strftime(self.__date_format),
            name=self.name,
            value=self.value,
        )