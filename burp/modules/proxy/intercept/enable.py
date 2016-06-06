from burp.modules import Connector
from burp.modules.proxy.intercept import ProxyIntercept


class ProxyInterceptEnable(ProxyIntercept):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'enable')

    def post(self) -> None:
        self._post((201,))
