# coding: utf-8
"""Test the Pombo entry point."""

# pylint: disable=import-error,redefined-outer-name,unused-argument

from collections import namedtuple

import pytest
import requests
from pombo import main, __version__, Pombo, WINDOWS

from .compat import patch

SUCCESS = 0
FAILURE = 1
Response = namedtuple("Response", "text")


@pytest.fixture
def swap(tmp_path):
    """Swap Pombo *ip_file* and *log_file* attributes."""
    ip_file_orig = Pombo.ip_file
    log_file_orig = Pombo.log_file

    Pombo.ip_file = str(tmp_path / "pombo")
    Pombo.log_file = str(tmp_path / "pombo.log")

    try:
        yield
    finally:
        Pombo.ip_file = ip_file_orig
        Pombo.log_file = log_file_orig


def test_argument_add(capsys, swap):
    """Test CLI argument: add."""

    def public_ip(_):
        """Mocked method to return a valid IP address."""
        return "127.0.0.1"

    with patch.object(Pombo, "public_ip", new=public_ip):
        assert main(["add"]) == SUCCESS
        assert "Adding IP 127.0.0.1" in capsys.readouterr()[0]
        with open(Pombo.ip_file) as ifile:
            lines = ifile.readlines()
        assert len(lines) == 1

        # Adding again should fo nothing
        assert main(["add"]) == SUCCESS
        assert "IP already known" in capsys.readouterr()[0]


def test_argument_add_network_error(capsys, swap):
    """Test CLI argument: add, with a simulated network error."""

    def public_ip(_):
        """Mocked method to return an valid IP address."""
        return ""

    with patch.object(Pombo, "public_ip", new=public_ip):
        assert main(["add"]) == FAILURE


@pytest.mark.parametrize("arg", ["help", "usage"])
def test_argument_help(arg, capsys):
    """Test CLI arguments: help and usage."""
    assert main([arg]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "Options" in out
    assert " add " in out
    assert " check " in out
    assert " help " in out
    assert " list " in out
    assert " update " in out
    assert " version " in out


@pytest.mark.parametrize("arg", ["list", "list_ips"])
def test_argument_list_inexistant(arg, capsys):
    """Test CLI argument: list and list_ips."""
    assert main([arg]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "There is no known IP address." in out


def test_argument_list_1_ip(capsys, swap):
    """Test CLI argument: list, when there is 1 IP address."""
    with open(Pombo.ip_file, "w") as ofile:
        ofile.write("127.0.0.1\n")

    assert main(["list"]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "IP hashes in {}".format(Pombo.ip_file) in out
    assert "127.0.0.1" in out


def test_argument_list_several_ips(capsys, swap):
    """Test CLI argument: list, when there are several IP addresses."""
    with open(Pombo.ip_file, "w") as ofile:
        ofile.write("127.0.0.1\n")
        ofile.write("127.0.0.2\n")

    assert main(["list"]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "IP hashes in {}".format(Pombo.ip_file) in out
    assert "127.0.0.1" in out
    assert "127.0.0.2" in out


def test_argument_update(capsys):
    """Test CLI arguments: update."""
    assert main(["update"]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "Version is up to date!" in out


@patch("requests.get")
def test_argument_update_site_error(mocked_obj, capsys):
    """Test CLI arguments: update, with a simulated network error."""
    mocked_obj.side_effect = requests.exceptions.ConnectionError("Mock'ed error")

    assert main(["update"]) == FAILURE

    out, err = capsys.readouterr()
    assert err == ""
    assert "Arf, check failed: Mock'ed error!" in out


@patch("requests.get")
def test_argument_update_newer(mocked_obj, capsys):
    """Test CLI arguments: update, when there is a new version available."""
    mocked_obj.return_value = Response(text="99.99.99")

    assert main(["update"]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "Yep! New version is available: 99.99.99" in out


@patch("requests.get")
@pytest.mark.parametrize(
    "new_ver", ["99.99a99", "99.99b99"],
)
def test_argument_update_newer_prelease(mocked_obj, new_ver, capsys):
    """Test CLI arguments: update, when there is a new pre-release version available."""
    mocked_obj.return_value = Response(text=new_ver)

    assert main(["update"]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "Development version available: {}".format(new_ver) in out


@patch("requests.get")
def test_argument_update_older(mocked_obj, capsys):
    """Test CLI arguments: update, when the current version is too new."""
    mocked_obj.return_value = Response(text="0.0.1")

    assert main(["update"]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "Ouhou! It seems that you are in advance on your time" in out


def test_argument_version(capsys):
    """Test CLI arguments: version."""
    assert main(["version"]) == SUCCESS

    out, err = capsys.readouterr()
    assert err == ""
    assert "Pombo {}".format(__version__) in out
    assert "I am using Python" in out
    assert "& MSS" in out
    assert "& IPy" in out
    assert "& request" in out

    if WINDOWS:
        assert "& VideoCapture" in out
        assert "& PIL" in out


def test_argument_unknown(capsys):
    """Test unknown CLI arguments."""
    assert main(["unknow"]) == FAILURE

    _, err = capsys.readouterr()
    assert 'Unknown argument "unknow" - try "help"' in err
