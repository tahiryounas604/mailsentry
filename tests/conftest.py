import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EXAMPLES = ROOT / "examples"


def load_example(name):
    from mailsentry.parsers import load_export

    path = EXAMPLES / name
    fmt = path.suffix.lstrip(".")
    return load_export(path.read_text(encoding="utf-8"), fmt)
