# coding: utf-8
"""Test Pombo helpers function."""

# pylint: disable=import-error

import pytest
from pombo import sizeof_fmt, to_bool


@pytest.mark.parametrize(
    "size, result",
    [
        (0, "0.0 B"),
        (1, "1.0 B"),
        (-1024, "-1.0 KiB"),
        (1024, "1.0 KiB"),
        (1024 * 1024, "1.0 MiB"),
        (pow(1024, 2), "1.0 MiB"),
        (pow(1024, 3), "1.0 GiB"),
        (pow(1024, 4), "1.0 TiB"),
        (pow(1024, 5), "1.0 PiB"),
        (pow(1024, 6), "1.0 EiB"),
        (pow(1024, 7), "1.0 ZiB"),
        (pow(1024, 8), "1.0 YiB"),
        (pow(1024, 9), "1,024.0 YiB"),
        (pow(1024, 10), "1,048,576.0 YiB"),
        (168963795964, "157.4 GiB"),
    ],
)
def test_sizeof_fmt(size, result):
    """ Simple tests for sizeof_fmt(). """
    assert sizeof_fmt(size) == result


def test_sizeof_fmt_arg():
    """ Simple tests for the *suffix* argument of sizeof_fmt(). """
    assert sizeof_fmt(168963795964, suffix="o") == "157.4 Gio"


@pytest.mark.parametrize(
    "value, result",
    [
        ("true", True),
        ("TRUe", True),
        ("on", True),
        ("1", True),
        ("yes", True),
        ("oui", True),
        ("OUI", True),
        ("", False),
        ("no", False),
        ("Non", False),
        ("false", False),
        ("0", False),
        ("bla bla bla !", False),
    ],
)
def test_to_bool(value, result):
    """ Simple tests for to_bool(). """
    assert to_bool(value) is result
