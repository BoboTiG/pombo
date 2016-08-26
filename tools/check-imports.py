# coding: utf-8
"""Pombo - check for needed modules."""
# pylint: disable=import-outside-toplevel,unused-import,invalid-name

import sys


def main():
    """Entry point."""
    ret = 0

    for module in ("mss", "requests", "IPy"):
        try:
            __import__(module)
        except ImportError:
            print(" ! Python module needed but not installed: %s" % module)
            ret = 1

    return ret


if __name__ == "__main__":
    sys.exit(main())
