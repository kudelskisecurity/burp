import requests
from typing import Mapping, Any, Optional, Tuple

from burp.models.errors import WeirdBurpResponseError


class Connector:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def __get_url(self, path: str) -> str:
        return 'http://{}:{}/{}'.format(self.host, self.port, path)

    def get(self, path: str) -> requests.Response:
        url = self.__get_url(path)
        return requests.get(url)

    def post(self, path: str, json: Optional[Mapping[str, Any]], file: Optional[bytes]) -> requests.Response:
        url = self.__get_url(path)
        files = file and {'file': file}
        return requests.post(url, json=json, files=files)

    def delete(self, path: str) -> requests.Response:
        url = self.__get_url(path)
        return requests.delete(url)


class Base:
    def __init__(self, connector: Connector, base_path: str) -> None:
        self.base_path = base_path
        self.__connector = connector

    def __resolve_path(self, path: Optional[str]) -> str:
        if path is None:
            return self.base_path
        return '/'.join([self.base_path, path])

    @staticmethod
    def __check_status_code(status_code: Tuple[int, ...], response: requests.Response) -> requests.Response:
        if response.status_code not in status_code:
            raise WeirdBurpResponseError(response)

        return response

    def _get(self, status_code: Tuple[int, ...], path: Optional[str] = None) -> requests.Response:
        rpath = self.__resolve_path(path)
        return self.__check_status_code(status_code, self.__connector.get(rpath))

    def _post(self, status_code: Tuple[int, ...], json: Optional[Mapping[str, Any]] = None,
              path: Optional[str] = None, file: Optional[bytes] = None) -> requests.Response:
        rpath = self.__resolve_path(path)
        return self.__check_status_code(status_code, self.__connector.post(rpath, json, file=file))

    def _delete(self, status_code: Tuple[int, ...], path: Optional[str] = None) -> requests.Response:
        rpath = self.__resolve_path(path)
        return self.__check_status_code(status_code, self.__connector.delete(rpath))
