from burp.modules import Base, Connector


class Spider(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'spider')

    def post(self, url: str) -> None:
        self._post((201,), json=dict(
            url=url,
        ))
