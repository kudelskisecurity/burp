from burp.modules import Connector, Base


class Scan(Base):
    def __init__(self, connector: Connector, sub_path: str) -> None:
        super().__init__(connector, '/'.join(['scan', sub_path]))
