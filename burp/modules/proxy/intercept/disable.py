from burp.modules import Connector
from burp.modules.proxy.intercept import ProxyIntercept


class ProxyInterceptDisable(ProxyIntercept):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'disable')

    def post(self) -> None:
        self._post((201,))
