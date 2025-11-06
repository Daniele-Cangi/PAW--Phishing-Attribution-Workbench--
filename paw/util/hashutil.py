
from blake3 import blake3
def blake3_hex(data: bytes) -> str:
    return blake3(data).hexdigest()
def file_blake3_hex(path: str) -> str:
    with open(path, "rb") as f:
        return blake3(f.read()).hexdigest()
