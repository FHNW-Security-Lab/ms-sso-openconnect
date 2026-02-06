"""JSON-RPC 2.0 protocol definitions for daemon IPC.

The daemon accepts JSON-RPC 2.0 requests over a Unix domain socket.
"""

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Request:
    """JSON-RPC 2.0 request."""
    method: str
    params: dict
    id: int

    @classmethod
    def from_json(cls, data: str) -> "Request":
        """Parse a JSON-RPC request."""
        obj = json.loads(data)
        return cls(
            method=obj.get("method", ""),
            params=obj.get("params", {}),
            id=obj.get("id", 0)
        )


@dataclass
class Response:
    """JSON-RPC 2.0 response."""
    result: Optional[dict]
    error: Optional[dict]
    id: int

    def to_json(self) -> str:
        """Serialize to JSON."""
        obj = {"jsonrpc": "2.0", "id": self.id}
        if self.error:
            obj["error"] = self.error
        else:
            obj["result"] = self.result
        return json.dumps(obj)

    @classmethod
    def success(cls, result: dict, request_id: int) -> "Response":
        """Create a success response."""
        return cls(result=result, error=None, id=request_id)

    @classmethod
    def error(cls, code: int, message: str, request_id: int) -> "Response":
        """Create an error response."""
        return cls(result=None, error={"code": code, "message": message}, id=request_id)


# Error codes
class ErrorCode:
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # Custom error codes
    ALREADY_CONNECTED = 1001
    NOT_CONNECTED = 1002
    CONNECTION_FAILED = 1003
    DISCONNECT_FAILED = 1004


# Method names
class Method:
    PING = "ping"
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    STATUS = "status"
