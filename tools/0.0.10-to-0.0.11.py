# coding: utf-8
"""Pombo: convert the configuration file from version 0.0.10 to 0.0.11."""
# pylint: disable=invalid-name

import sys


def main():
    """Entry point."""

    conf = "/etc/pombo.conf"
    if sys.platform == "win32":
        conf = "c:\\pombo\\pombo.conf"

    data = b""
    with open(conf, "rb") as config_file:
        data = config_file.read()

    if not data:
        print("! Impossible to read the configuration file.")
        return 1

    data = data.replace("serverurl", "server_url")
    data = data.replace("checkfile", "check_file")
    data = data.replace("onlyonipchange", "only_on_ip_change")

    with open(conf, "wb") as config_file:
        config_file.write(data)

    return 0


if __name__ == "__main__":
    sys.exit(main())
