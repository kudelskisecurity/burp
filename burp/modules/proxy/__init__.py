from burp.modules import Connector, Base


class Proxy(Base):
    def __init__(self, connector: Connector, sub_path: str) -> None:
        super().__init__(connector, '/'.join(['proxy', sub_path]))
