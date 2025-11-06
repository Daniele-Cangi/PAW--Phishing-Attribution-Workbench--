
import os, shutil, json, re

class BytesEncoder(json.JSONEncoder):
    """Custom JSON encoder that converts bytes to hex strings"""
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)

def ensure_dir(p): os.makedirs(p, exist_ok=True)

def write_json(path, obj):
    """Write `obj` as JSON to `path`. Create parent directories if missing."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, cls=BytesEncoder)

def write_text(path, text):
    """Write text to `path`. Create parent directories if missing."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
def read_json(path):
    """Read JSON from `path`. Returns None if file doesn't exist."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError):
        return None

def sanitize_case_id(s: str):
    return re.sub(r'[^A-Za-z0-9\-_:]', '-', s)
