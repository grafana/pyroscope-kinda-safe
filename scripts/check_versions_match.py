#!/usr/bin/env python3
import sys

from cargo_version import cargo_version


def main() -> int:
    kindasafe = cargo_version("kindasafe")
    kindasafe_init = cargo_version("kindasafe_init")
    if kindasafe != kindasafe_init:
        print(f"error: kindasafe ({kindasafe}) != kindasafe_init ({kindasafe_init})")
        return 1
    print(f"kindasafe versions in sync: {kindasafe}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
