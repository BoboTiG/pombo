# coding: utf-8
"""Test Pombo implementation."""

# pylint: disable=import-error

import os.path
from getpass import getuser

import pytest
from pombo import WINDOWS

from .compat import patch


def test_current_user_normal(pombo):
    """ The method should correctly guess the user name. """
    assert pombo.current_user() == getuser()


@pytest.mark.skipif(WINDOWS, reason="Unix only.")
@pytest.mark.parametrize(
    "value, result",
    [
        ("tiger-222 tty1         2020-02-13 22:57", "tiger-222"),
        (
            "\n".join(
                [
                    "tiger-222 console  Feb 11 14:11",
                    "tiger-222 ttys001  Feb 12 11:44",
                    "tiger-222 ttys004  Feb 21 11:06",
                ]
            ),
            "tiger-222",
        ),
        ("santoine :0           2017-04-20 08:27 (:0)**", "santoine"),
    ],
)
def test_current_user_handled_schemas(value, result, pombo):
    """ Try supported inputs while guessing the user name. """

    def runprocess(*_, **__):
        return value

    with patch.object(pombo, "runprocess", new=runprocess):
        assert pombo.current_user() == result


def test_ip_changed(pombo):
    """ Test ip_change(). """
    # First time an IP is seen, the method returns True
    assert pombo.ip_changed("127.0.0.1")

    # Then it should return False
    assert not pombo.ip_changed("127.0.0.1")

    # A new IP is seen, meaning that the machine is stolen, it should return True
    assert pombo.ip_changed("127.0.0.2")


def test_need_report_default_behavior(pombo):
    """ Test the default behavior of need_report(), e.g.: when only_on_ip_change is false. """
    report_needed, is_stolen = pombo.need_report("127.0.0.1")
    assert not report_needed
    assert not is_stolen

    report_needed, is_stolen = pombo.need_report("127.0.0.2")
    assert not report_needed
    assert not is_stolen

    # Mimic a stolen machine


def test_need_report_on_ip_change(pombo):
    """ Test the behavior of need_report() when only_on_ip_change is true. """
    pombo.configuration["only_on_ip_change"] = True
    report_needed, is_stolen = pombo.need_report("127.0.0.1")
    assert report_needed
    assert not is_stolen

    report_needed, is_stolen = pombo.need_report("127.0.0.2")
    assert report_needed
    assert not is_stolen


def test_public_ip(pombo):
    """ Ensure we can get the public IP. """
    assert pombo.public_ip()


def test_screenshot(pombo, tmp_path):
    """ Test the screenshot feature. """
    files = pombo.screenshot(str(tmp_path))
    assert len(files) >= 1
    for screenshot in files:
        assert os.path.isfile(screenshot)


def test_screenshot_disabled(pombo):
    """ Test the screenshot feature when it is disabled by the user. """
    pombo.configuration["screenshot"] = False
    assert not pombo.screenshot("")


def test_screenshot_no_user(pombo):
    """ Test the screenshot feature when the user cannot get retrieved. """

    def current_user():
        return ""

    with patch.object(pombo, "current_user", new=current_user):
        assert not pombo.screenshot("")


def test_system_report(pombo):
    """ Test the report feature. """
    report = pombo.system_report("127.0.0.1")
    assert "Pombo" in report
    assert "Username :" in report
    assert "Computer :" in report
    assert "Serial/N :" in report
    assert "System   :" in report
    assert "Public IP: 127.0.0.1" in report
    assert "Date/time:" in report
    assert "Network config:" in report
    assert "Nearby wireless access points:" in report
    assert "Network routes:" in report
    assert "Current network connections:" in report
    assert "Report end." in report


def test_snapshot(pombo):
    """ Test the snapshot feature. """

    def system_report(current_ip):
        """ Already tested in test_system_report(). """
        return ""

    def send(filename, data):
        assert os.path.isfile(filename)
        assert isinstance(data, bytes)

    with patch.object(pombo, "system_report", new=system_report):
        with patch.object(pombo, "snapshot_sendto_server", new=send):
            pombo.snapshot("127.0.0.1")
