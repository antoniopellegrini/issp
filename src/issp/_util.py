def xor(data: bytes, key: bytes) -> bytes:
    size = len(data)
    if size > len(key):
        err_msg = "Key is too short"
        raise ValueError(err_msg)
    return bytes(data[i] ^ key[i] for i in range(size))


def zero_pad(data: bytes, size: int) -> bytes:
    padding = size - len(data) % size
    return data + bytes(padding) if padding else data
