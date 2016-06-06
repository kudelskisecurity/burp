from burp.modules import Base, Connector


class Alert(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'alert')

    def post(self, message: str) -> None:
        self._post((201,), json=dict(
            message=message,
        ))
