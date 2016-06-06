from burp.modules import Connector
from burp.modules.proxy import Proxy


class ProxyIntercept(Proxy):
    def __init__(self, connector: Connector, sub_path: str) -> None:
        super().__init__(connector, '/'.join(['intercept', sub_path]))
