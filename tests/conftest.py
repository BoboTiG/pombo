# coding: utf-8
"""Useful shared fixtures."""

# pylint: disable=import-error

# Needed for Python 2.7 and ConfigParser
from __future__ import unicode_literals

import os.path

import pytest
from pombo import Pombo, LINUX, MAC

from .compat import ConfigParser


@pytest.fixture
def pombo(tmp_path):
    """Return an instance of the Pombo class with custom attributes.
    It will also setup the configuration file.
    """

    cls = Pombo(testing=True)
    cls.conf = str(tmp_path / "pombo.conf")
    cls.ip_file = str(tmp_path / "pombo")
    cls.log_file = str(tmp_path / "pombo.log")

    # For better coverage ...
    with pytest.raises(SystemExit):
        cls.config()

    root = os.path.dirname(os.path.dirname(__file__))

    conf = ConfigParser()
    conf.read([os.path.join(root, "pombo.conf")])
    with open(cls.conf, "w") as ofile:
        conf.write(ofile)
    with pytest.raises(SystemExit):
        cls.config()

    conf["General"]["server_url"] = "http://localhost:8000"
    conf["General"]["gpgkeyid"] = "i_dont_wanna_use_encryption_and_i_assume"
    if LINUX:
        conf["Commands"]["camshot"] = ""
        conf["Commands"]["network_config"] = "/sbin/ip a"
        conf["Commands"]["network_trafic"] = "/bin/ss -putn"
        conf["Commands"]["traceroute"] = "/usr/bin/traceroute -q1 www.example.com"
        conf["Commands"]["wifi_access_points"] = ""
    elif MAC:
        conf["Commands"]["camshot"] = ""
        conf["Commands"]["network_config"] = "/sbin/ifconfig -a"
        conf["Commands"]["network_trafic"] = "/bin/ss -putn"
        conf["Commands"]["traceroute"] = "/usr/sbin/netstat -utn"
        conf["Commands"][
            "wifi_access_points"
        ] = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport -s"
    else:
        conf["Commands"]["camshot"] = "no"

    with open(cls.conf, "w") as ofile:
        conf.write(ofile)

    cls.configuration = cls.config()

    yield cls
