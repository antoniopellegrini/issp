def xor(a: bytes, b: bytes, *, add_zero_padding: bool = False) -> bytes:
    a_size, b_size = len(a), len(b)
    if a_size > b_size:
        if add_zero_padding:
            b = zero_pad(b, a_size)
        else:
            err_msg = f"RHS ({b_size} B) is too short for LHS ({a_size} B)"
            raise ValueError(err_msg)
    return bytes(a[i] ^ b[i] for i in range(a_size))


def zero_pad(data: bytes, size: int) -> bytes:
    padding = size - len(data) % size
    return data + bytes(padding) if padding else data


def byte_size(number: int) -> int:
    return (number.bit_length() + 7) // 8
