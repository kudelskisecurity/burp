from burp.modules import Base, Connector


class State(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'state')

    def get(self) -> bytes:
        ret = self._get((200,))
        return ret.content

    def post(self, state: bytes) -> None:
        self._post((200,), file=state)
