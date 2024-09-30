from abc import ABC, abstractmethod

from . import _log as log


class Layer(ABC):
    @abstractmethod
    def send(self, message: bytes) -> None:
        pass

    @abstractmethod
    def receive(self) -> bytes | None:
        pass


class Channel(Layer):
    def __init__(self) -> None:
        self._message: bytes | None = None

    def send(self, message: bytes) -> None:
        self._message = message

    def receive(self) -> bytes | None:
        return self._message


class Actor:
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        self.name = name
        self._quiet = quiet

    def send(self, layer: Layer, message: bytes) -> None:
        try:
            layer.send(message)
        except Exception as e:
            self._log("was unable to send: %s (%s)", _try_decode(message), str(e))
        else:
            self._log("sent: %s", _try_decode(message))

    def receive(self, layer: Layer) -> bytes | None:
        try:
            message = layer.receive()
        except Exception as e:
            self._log("was unable to receive: %s", str(e))
            return None
        self._log("received: %s", _try_decode(message))
        return message

    def _log(self, fmt: str, *args: object) -> None:
        if not self._quiet:
            log.info("%s " + fmt, self.name, *args)


def _try_decode(message: bytes | None) -> bytes | str | None:
    try:
        return message.decode() if message else ""
    except UnicodeDecodeError:
        return message
