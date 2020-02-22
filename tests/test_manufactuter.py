# coding: utf-8
"""Test Pombo manufacturer retrieval logic."""

# pylint: disable=import-error

import pytest

from .compat import patch


@pytest.mark.parametrize(
    "values, expected",
    [
        (
            ["Intel Corporation", "NUC6i7KYB", "H90766-406"],
            "Intel Corporation-NUC6i7KYB-H90766-406",
        ),
        (
            ["", "", "", "Intel Corporation", "NUC6i7KYB", "H90766-406"],
            "Intel Corporation-NUC6i7KYB-H90766-406",
        ),
    ],
)
def test_get_manufacturer_linux(values, expected, pombo):
    """ Test get_manufacturer() on GNU/Linux """

    def runprocess(*_, **__):
        return values.pop(0)

    with patch.object(pombo, "runprocess", new=runprocess):
        with patch.object(pombo, "is_windows", new=lambda: False):
            with patch.object(pombo, "is_mac", new=lambda: False):
                assert pombo.get_manufacturer() == expected


@pytest.mark.parametrize(
    "value, result",
    [
        (
            "      Model Name: MacBook Pro\n      Model Identifier: MacBookPro12,1",
            "MacBook Pro-MacBookPro12,1",
        ),
    ],
)
def test_get_manufacturer_mac(value, result, pombo):
    """ Test get_manufacturer() on macOS. """

    def runprocess(*_, **__):
        return value

    with patch.object(pombo, "runprocess", new=runprocess):
        with patch.object(pombo, "is_windows", new=lambda: False):
            with patch.object(pombo, "is_mac", new=lambda: True):
                assert pombo.get_manufacturer() == result


@pytest.mark.parametrize(
    "value, result",
    [
        (
            "Name=VirtualBox\r\nVendor=innotek GmbH\r\nVersion=1.2",
            "innotek GmbH-VirtualBox-1.2",
        ),
        (
            "Name=7459PQ3\nVendor=LENOVO\nVersion=ThinkPad X200",
            "LENOVO-7459PQ3-ThinkPad X200",
        ),
        ("Name=0\r\nVendor=0", "Unknown"),
    ],
)
def test_get_manufacturer_windows(value, result, pombo):
    """ Test get_manufacturer() on Windows. """

    def runprocess(*_, **__):
        return value

    with patch.object(pombo, "runprocess", new=runprocess):
        with patch.object(pombo, "is_windows", new=lambda: True):
            assert pombo.get_manufacturer() == result
