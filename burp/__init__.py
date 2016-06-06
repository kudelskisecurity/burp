from burp.modules import Connector
from burp.modules.alert import Alert
from burp.modules.jar import Jar
from burp.modules.proxy.intercept.disable import ProxyInterceptDisable
from burp.modules.proxy.intercept.enable import ProxyInterceptEnable
from burp.modules.proxyhistory import ProxyHistory
from burp.modules.scan.active import ScanActive
from burp.modules.scan.passive import ScanPassive
from burp.modules.scanissues import ScanIssues
from burp.modules.scope import Scope
from burp.modules.send import Send
from burp.modules.sitemap import SiteMap
from burp.modules.spider import Spider
from burp.modules.state import State


class Burp:
    def __init__(self, host: str, port: int) -> None:
        connector = Connector(host, port)

        self.scope = Scope(connector)
        self.scanissues = ScanIssues(connector)
        self.spider = Spider(connector)
        self.jar = Jar(connector)

        class Scan:
            def __init__(self) -> None:
                self.active = ScanActive(connector)
                self.passive = ScanPassive(connector)

        self.scan = Scan()

        self.send = Send(connector)
        self.alert = Alert(connector)
        self.sitemap = SiteMap(connector)
        self.proxyhistory = ProxyHistory(connector)
        self.state = State(connector)

        class Proxy:
            class Intercept:
                def __init__(self) -> None:
                    self.enable = ProxyInterceptEnable(connector)
                    self.disable = ProxyInterceptDisable(connector)

            def __init__(self) -> None:
                self.intercept = Proxy.Intercept()

        self.proxy = Proxy()
