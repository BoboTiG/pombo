# coding: utf-8
"""Test Pombo serial number retrieval logic."""

# pylint: disable=import-error

import pytest

from .compat import patch


@pytest.mark.parametrize(
    "values, result",
    [
        (["", ""], "Unknown"),
        (["", "BTKY707000VP"], "BTKY707000VP"),
        (["BTKY707000VP"], "BTKY707000VP"),
    ],
)
def test_get_serial_linux(values, result, pombo):
    """ Test get_serial() on GNU/Linux. Only the logic is tests. """

    def runprocess(*_, **__):
        return values.pop(0)

    with patch.object(pombo, "runprocess", new=runprocess):
        with patch.object(pombo, "is_windows", new=lambda: False):
            assert pombo.get_serial() == result


@pytest.mark.parametrize("value, result", [(" C02SL1DFFVH6", "C02SL1DFFVH6")])
def test_get_serial_mac(value, result, pombo):
    """ Test get_serial() on macOS. """

    def runprocess(*_, **__):
        return value

    with patch.object(pombo, "runprocess", new=runprocess):
        with patch.object(pombo, "is_windows", new=lambda: False):
            assert pombo.get_serial() == result


@pytest.mark.parametrize(
    "value, result",
    [
        ("\r\n\r\nERR=1234\r\n\r\n", "Unknown"),
        ("\r\n\r\nSerialNumber=0\r\n\r\n", "Unknown"),
        ("SerialNumber=L3AKP8N", "L3AKP8N"),
    ],
)
def test_get_serial_windows(value, result, pombo):
    """ Test get_serial() on Windows. """

    def runprocess(*_, **__):
        return value

    with patch.object(pombo, "runprocess", new=runprocess):
        with patch.object(pombo, "is_windows", new=lambda: True):
            assert pombo.get_serial() == result
