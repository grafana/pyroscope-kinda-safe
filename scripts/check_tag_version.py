#!/usr/bin/env python3
import os
import sys

from cargo_version import cargo_version


def main() -> int:
    tag_version = os.environ.get("TAG", "").removeprefix("kindasafe-")
    version = cargo_version("kindasafe")
    if tag_version != version:
        print(f"error: tag version ({tag_version}) does not match kindasafe/Cargo.toml version ({version})")
        return 1
    print(f"tag version ({tag_version}) matches kindasafe/Cargo.toml version ({version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
