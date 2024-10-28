from __future__ import annotations

import base64
import json
from abc import ABC, abstractmethod

from . import _log as log


class Layer(ABC):
    @abstractmethod
    def send(self, message: bytes) -> None:
        pass

    @abstractmethod
    def receive(self) -> bytes | None:
        pass

    def __init__(self, layer: Layer | None = None) -> None:
        self.upper_layer: Layer | None = None
        self.lower_layer = layer
        if layer:
            layer.upper_layer = self

    def __or__(self, lower_layer: object) -> Layer:
        if not isinstance(lower_layer, Layer):
            err_msg = f"Unsupported operand type(s) for |: '{type(self)}' and '{type(lower_layer)}'"
            raise TypeError(err_msg)
        root_layer = self.bottom_layer()
        if isinstance(root_layer, PhysicalLayer):
            err_msg = "You've hit rock bottom, my friend"
            raise TypeError(err_msg)
        root_layer.lower_layer = lower_layer
        lower_layer.upper_layer = root_layer
        return self

    def get_layer(self, depth: int) -> Layer:
        if depth == 0:
            return self
        if depth < 0:
            if self.lower_layer is None:
                return self
            return self.lower_layer.get_layer(depth + 1)
        if self.upper_layer is None:
            return self
        return self.upper_layer.get_layer(depth - 1)

    def top_layer(self) -> Layer:
        return self if self.upper_layer is None else self.upper_layer.top_layer()

    def bottom_layer(self) -> Layer:
        return self if self.lower_layer is None else self.lower_layer.bottom_layer()


class PhysicalLayer(Layer):
    pass


class Channel(PhysicalLayer):
    def __init__(self) -> None:
        super().__init__()
        self._message: bytes | None = None

    def send(self, message: bytes) -> None:
        self._message = message

    def receive(self) -> bytes | None:
        return self._message


class Actor:
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        self.name = name
        self._quiet = quiet

    def send(self, layer: Layer, message: bytes | object) -> None:
        try:
            layer.send(_try_encode(message))
        except Exception as e:
            self._log("was unable to send: %s (%s)", message, str(e))
        else:
            self._log("sent: %s", _try_decode(message))

    def receive(self, layer: Layer, *, decode: bool = True) -> bytes | object | None:
        try:
            message = layer.receive()
        except Exception as e:
            self._log("was unable to receive: %s", str(e))
            return None
        if decode:
            message = _try_decode(message)
        self._log("received: %s", message)
        return message

    def _log(self, fmt: str, *args: object) -> None:
        if not self._quiet:
            log.info("%s " + fmt, self.name, *args)


def _default_encode(o: object) -> str | object:
    if isinstance(o, bytes):
        return base64.b64encode(o).decode("ascii")
    err_msg = f"Object of type '{o.__class__.__name__}' is not JSON serializable"
    raise TypeError(err_msg)


def _default_decode(d: dict) -> object:
    return {key: base64.b64decode(value) if "b64" in key else value for key, value in d.items()}


def _try_encode(message: bytes | object) -> bytes:
    try:
        if isinstance(message, bytes):
            return message
        return json.dumps(message, default=_default_encode).encode()
    except Exception:
        return message


def _try_decode(message: bytes | None) -> bytes | object | None:
    try:
        return None if message is None else json.loads(message, object_hook=_default_decode)
    except Exception:
        return message
