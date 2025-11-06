
import json, os
from ..util.hashutil import blake3_hex

def merkle_root(files):
    # Simple pairwise Merkle using BLAKE3 hex strings
    if not files: return None
    level = [blake3_hex(open(f,"rb").read()).encode() for f in files]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i+1] if i+1 < len(level) else level[i]
            nxt.append(blake3_hex(a + b).encode())
        level = nxt
    return level[0].decode()

def write_index(path, mapping):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)
