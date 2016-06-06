from burp.models.send import Tool, Request
from burp.modules import Base, Connector


class Send(Base):
    def __init__(self, connector: Connector) -> None:
        super().__init__(connector, 'send')

    def post(self, tool: Tool, request: Request) -> None:
        self._post((201,), json=request.to_json(), path=tool.value)
