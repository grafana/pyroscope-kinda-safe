import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cargo_version(crate: str) -> str:
    with open(ROOT / crate / "Cargo.toml", "rb") as f:
        return tomllib.load(f)["package"]["version"]
