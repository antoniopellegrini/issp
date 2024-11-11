import random

from ._communication import Actor
from ._functions import sha256


def biometric_template(actor: Actor, noise: float = 0.005) -> list[float]:
    template = sha256(actor.name.encode())
    template = [b / 256.0 for b in template]
    if noise:
        for i in range(len(template)):
            template[i] += random.normalvariate(0, noise)
    return template


def euclidean_distance(a: list[float], b: list[float]) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b, strict=True)) ** 0.5


def euclidean_similarity(a: list[float], b: list[float]) -> float:
    return 1.0 / (1.0 + euclidean_distance(a, b))
