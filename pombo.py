#!/usr/bin/env python3
# coding: utf-8
"""
Pombo
Theft-recovery tracking open-source software
https://github.com/BoboTiG/pombo
http://sebsauvage.net/pombo

This program is distributed under the OSI-certified zlib/libpnglicense .
http://www.opensource.org/licenses/zlib-license.php

This software is provided 'as-is', without any express or implied warranty.
In no event will the authors be held liable for any damages arising from
the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it freely,
subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
       claim that you wrote the original software. If you use this software
       in a product, an acknowledgment in the product documentation would be
       appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not
       be misrepresented as being the original software.

    3. This notice may not be removed or altered from any source distribution.
"""

from __future__ import print_function

# pylint: disable=import-error,too-many-lines,useless-object-inheritance

import hashlib
import hmac
import io
import logging
import os
import platform
import subprocess
from socket import gaierror
import sys
import time
import zipfile
from base64 import b64encode
from datetime import datetime
from distutils.version import StrictVersion
from locale import getdefaultlocale
from tempfile import gettempdir

import IPy
import mss
import requests
import requests.exceptions

try:
    from configparser import Error, ConfigParser
    from urllib.parse import urlsplit
except ImportError:  # pragma: no cover
    from ConfigParser import Error, ConfigParser  # type: ignore
    from urlparse import urlsplit  # type: ignore

try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:  # pragma: no cover
        from typing import Any, Dict, List, Optional, Tuple, Union
except ImportError:  # pragma: no cover
    pass

if sys.platform == "win32":  # pragma: no cover
    from PIL import Image
    from VideoCapture import Device

__version__ = "1.1b1"

LINUX = sys.platform.startswith("linux")
MAC = sys.platform == "darwin"
WINDOWS = sys.platform == "win32"
CURRENT_OS = {"Linux": "Linux", "Darwin": "Mac", "Windows": "Windows"}[
    platform.system()
]
ENCODING = sys.stdin.encoding or getdefaultlocale()[1] or "utf-8"
VC_VERSION = "0.9.5"
URL = "https://github.com/BoboTiG/pombo"
UPLINK = "https://raw.github.com/BoboTiG/pombo/master/VERSION"
DEFAULTS = {
    "gpgkeyid": "",
    "password": "",
    "server_url": "",
    "check_file": "",
    "time_limit": 15,
    "email_id": "",
    "only_on_ip_change": False,
    "enable_log": False,
    "use_proxy": False,
    "use_env": False,
    "http_proxy": "",
    "https_proxy": "",
    "auth_server": "",
    "auth_user": "",
    "auth_pswd": "",
    "gpg_binary": "",
    "network_config": "",
    "wifi_access_points": "",
    "traceroute": "",
    "network_trafic": "",
    "screenshot": True,
    "camshot": "",
    "camshot_filetype": "",
}


# ----------------------------------------------------------------------
# --- [ Routines ] -----------------------------------------------------
# ----------------------------------------------------------------------
def sizeof_fmt(value, suffix="B"):
    # type: (int, str) -> str
    """
    Human readable version of file size.
    Supports:
        - all currently known binary prefixes (https://en.wikipedia.org/wiki/Binary_prefix)
        - negative and positive numbers
        - numbers larger than 1,000 Yobibytes
        - arbitrary units
    Examples:
        >>> sizeof_fmt(168963795964)
        "157.4 GiB"
        >>> sizeof_fmt(168963795964, suffix="o")
        "157.4 Gio"
    Source: https://stackoverflow.com/a/1094933/1117028
    """
    val = float(value)
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(val) < 1024.0:
            return "{:3.1f} {}{}".format(val, unit, suffix)
        val /= 1024.0
    return "{:,.1f} Yi{}".format(val, suffix)


def hash_string(current_ip):
    # type: (str) -> str
    """ IP hash method - could be easily modifed. """
    return hashlib.sha256(current_ip.encode()).hexdigest()


def printerr(string=""):
    # type: (str) -> None
    """ Print an error message to STDERR. """
    sys.stderr.write(string + "\n")


def to_bool(value=""):
    # type: (str) -> bool
    """ Return a boolean of a given string. """
    return str(value).lower() in {"true", "on", "1", "yes", "oui"}


# ----------------------------------------------------------------------
# --- [ Classes ] ------------------------------------------------------
# ----------------------------------------------------------------------
class Pombo(object):
    """ Pombo core. """

    # pylint: disable=too-many-public-methods,too-many-instance-attributes

    conf = "c:\\pombo\\pombo.conf" if WINDOWS else "/etc/pombo.conf"
    ip_file = "c:\\pombo\\pombo" if WINDOWS else "/var/local/pombo"
    log_file = "c:\\pombo\\pombo.log" if WINDOWS else "/var/log/pombo.log"

    def __init__(self, testing=False):
        # type: (bool) -> None
        """ Pombo initializations. """
        self.testing = bool(testing)
        self.stolen_var = False
        self.stolen_last_update = 0.0
        self.configuration = {}  # type: Dict[str, Any]

        self.__log = ""
        self.__user = ""

    @property
    def user(self):
        # type: () -> str
        """ Get the current logged-in user. """
        if not self.__user:
            self.__user = self.current_user()
        return self.__user

    @property
    def log(self):
        """ Session logger. """
        if not self.__log:
            self.__log = logging.getLogger("pombo")
            self.install_log_handlers()
        return self.__log

    @staticmethod
    def is_mac():
        # type: () -> bool
        """ Return True when running on macOS. Used in tests too. """
        return MAC

    @staticmethod
    def is_windows():
        # type: () -> bool
        """ Return True when running on Windows. Used in tests too. """
        return WINDOWS

    def config(self):
        # type: () -> Dict[str, Any]
        """ Get configuration from conf file. """

        self.log.debug("Loading configuration")
        try:
            conf = ConfigParser(defaults=DEFAULTS)  # type: ignore
            func = getattr(conf, "read_file", None) or getattr(conf, "readfp")
            with io.open(self.conf, encoding="utf-8") as ifile:
                func(ifile)
        except (OSError, IOError, Error) as ex:
            self.log.error(ex)
            sys.exit(1)

        # Primary parameters
        config = {
            "gpgkeyid": conf.get("General", "gpgkeyid"),
            "password": conf.get("General", "password"),
            "server_url": conf.get("General", "server_url"),
            "check_file": conf.get("General", "check_file"),
            "time_limit": conf.getint("General", "time_limit"),  # type: ignore
        }
        error = False
        for key in config:
            if not config[key]:
                self.log.error("config error: empty %s parameter.", key)
                error = True
        if error:
            self.log.critical("Pombo has to stop, please check parameters.")
            sys.exit(0)

        # Secondary parameters (auth., email, commands, ...)
        config["email_id"] = conf.get("General", "email_id")
        config["only_on_ip_change"] = conf.getboolean(  # type: ignore
            "General", "only_on_ip_change"
        )
        config["enable_log"] = conf.getboolean("General", "enable_log")  # type: ignore
        config["use_proxy"] = conf.getboolean("General", "use_proxy")  # type: ignore
        config["use_env"] = conf.getboolean("General", "use_env")  # type: ignore
        config["http_proxy"] = conf.get("General", "http_proxy")
        config["https_proxy"] = conf.get("General", "https_proxy")
        config["auth_server"] = conf.get("General", "auth_server")
        config["auth_user"] = conf.get("General", "auth_user")
        config["auth_pswd"] = conf.get("General", "auth_pswd")
        config["gpg_binary"] = conf.get("Commands", "gpg_binary")
        config["network_config"] = conf.get("Commands", "network_config")
        config["wifi_access_points"] = conf.get("Commands", "wifi_access_points")
        config["traceroute"] = conf.get("Commands", "traceroute")
        config["network_trafic"] = conf.get("Commands", "network_trafic")
        config["screenshot"] = conf.getboolean("Commands", "screenshot")  # type: ignore
        config["camshot"] = conf.get("Commands", "camshot")
        config["camshot_filetype"] = conf.get("Commands", "camshot_filetype")

        # Informations logging
        if not config["enable_log"] and len(self.log.handlers) > 1:
            self.log.debug("Disabling console logger")
            del self.log.handlers[1]

        return config

    def current_user(self):
        # type: () -> str
        """ Return the user who is currently logged in and uses the X
            session. None if could not be determined.
        """

        user = ""

        if self.is_windows():
            user = self.runprocess(["echo", "%USERNAME%"], useshell=True)
        else:
            lines = self.runprocess(["who", "-s"], useshell=True).splitlines()
            for line in lines:
                if "tty" in line or "pts" in line or ":0" in line:
                    user = line.split(" ")[0].strip()
                    if ":0" in line:
                        break

        self.log.debug("Username is %r", user)
        return user

    def get_manufacturer(self):
        # type: () -> str
        """ Get the manufacturer. """

        if self.is_windows():
            cmd = "wmic csproduct get vendor, name, version /value"
            res = self.runprocess(cmd, useshell=True).strip().splitlines()
            if len(res) < 3:
                manufacturer = "Unknown"
            else:
                manufacturer = "-".join(
                    [
                        res[1].split("=")[1].strip(),
                        res[0].split("=")[1].strip(),
                        res[2].split("=")[1].strip(),
                    ]
                )
        elif self.is_mac():
            cmd = "/usr/sbin/system_profiler SPHardwareDataType | grep Model"
            res = self.runprocess(cmd, useshell=True).strip().splitlines()
            manufacturer = "-".join(
                [res[0].split(": ")[1].strip(), res[1].split(": ")[1].strip()]
            )
        else:
            manufacturer = ""
            # Try first the system data
            res = [
                self.runprocess(
                    "/usr/sbin/dmidecode --string " + info, useshell=True
                ).strip()
                for info in (
                    "system-manufacturer",
                    "system-product-name",
                    "system-version",
                )
            ]
            if set(res) == set([""]):
                # Fallback on the baseboard
                res = [
                    self.runprocess(
                        "/usr/sbin/dmidecode --string " + info, useshell=True
                    ).strip()
                    for info in (
                        "baseboard-manufacturer",
                        "baseboard-product-name",
                        "baseboard-version",
                    )
                ]
            manufacturer = "-".join(res)
        self.log.debug("Manufacturer is %r", manufacturer)
        return manufacturer

    def get_serial(self):
        # type: () -> str
        """ Get the serial number. """

        serial = "Unknown"
        cmds = {
            "Linux": [
                # Try first the system data
                "/usr/sbin/dmidecode --string system-serial-number",
                # Fallback on the baseboard
                "/usr/sbin/dmidecode --string baseboard-serial-number",
            ],
            "Mac": [
                (
                    "/usr/sbin/system_profiler SPHardwareDataType"
                    " | grep system | tail -1 | cut -d: -f2"
                )
            ],
            "Windows": ["wmic bios get serialnumber /value"],
        }

        for cmd in cmds[CURRENT_OS]:
            res = self.runprocess(cmd, useshell=True).strip()
            if not res:
                continue

            if self.is_windows():
                parts = res.split("=")
                if not parts[0].startswith("ERR") and parts[1] != "0":
                    serial = parts[1]
                    break
            elif res != "System Serial Number":
                serial = res
                break

        self.log.debug("Serial number is %r", serial)
        return serial

    def install_log_handlers(self, level=logging.INFO):
        # type: (int) -> None
        """ Install log handlers: one for the file log_file and one for
            the console.
        """

        self.log.handlers = []
        self.log.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(funcName)s::L%(lineno)d %(message)s"
        )

        # Log to file
        try:
            file_handler = logging.FileHandler(self.log_file, "a")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.log.addHandler(file_handler)
            self.log.debug("Log file is %s", self.log_file)
        except IOError as ex:
            printerr(str(ex))

        # Log to console
        steam_handler = logging.StreamHandler()
        steam_handler.setLevel(level)
        self.log.addHandler(steam_handler)

    def ip_changed(self, curr_ip):
        # type: (str) -> bool
        """ Check if current_ip is already known from ip_file. """

        # Read previous IP
        if not os.path.isfile(self.ip_file):
            self.log.info("First run, writing down IP in %r.", self.ip_file)
            with open(self.ip_file, "w+") as fileh:
                fileh.write(hash_string(curr_ip))
            return True

        with open(self.ip_file) as fileh:
            prev_ips = fileh.readlines()
            if hash_string(curr_ip) not in [ip.strip() for ip in prev_ips]:
                self.log.info("IP has changed.")
                return True
            self.log.info("IP has not changed.")

        return False

    def need_report(self, current_ip):
        # type: (str) -> Tuple[bool, bool]
        """ Return the stolen state or the computer IP.
            If one of them is True, so we need to send a report.

            Returned values: (report_needed: Bool, is_stolen: Bool)
                report_needed: True if a report is needed
                is_stolen: True if computer is marked as stolen
        """

        is_stolen = self.stolen()
        if is_stolen:
            return True, True

        if not self.configuration["only_on_ip_change"]:
            self.log.info("Skipping check based on IP change.")
            return False, False

        return self.ip_changed(current_ip), False

    def public_ip(self):
        # type: () -> str
        """ Returns your public IP address.
            Output: The IP address in string format.
                    None if not internet connection is available.
        """

        if not self.configuration:
            self.configuration = self.config()

        current_ip = ""
        for distant in self.configuration["server_url"].split("|"):
            self.log.info("Retrieving IP address from %s", urlsplit(distant).netloc)
            try:
                current_ip = self.request_url(distant, "get", {"myip": "1"})
                self.log.debug("Server returned public IP %r", current_ip)
                IPy.IP(current_ip)
            except (gaierror, ValueError) as ex:
                self.log.error(ex)
                current_ip = ""
            return current_ip

        # Make sure we are connected to the internet:
        # (If the computer has no connexion to the internet, it's no use
        # accumulating snapshots.)
        if not current_ip:
            self.log.error(
                "Computer does not seem to be connected to the internet. Aborting."
            )
        return ""

    def request_url(self, url, method="get", params=None):
        # type: (str, str, Dict[str, Any]) -> str
        """ Make a request with all options "aux petits oignons".
        """

        # Proxies
        proxies = {}
        if self.configuration["use_proxy"]:
            if self.configuration["use_env"]:
                proxies["http"] = os.getenv("http_proxy")
                proxies["https"] = os.getenv("https_proxy")
            else:
                proxies["http"] = self.configuration["http_proxy"]
                proxies["https"] = self.configuration["https_proxy"]

        ret = ""
        parts = urlsplit(url)
        ssl_cert_verif = parts.scheme == "https"
        auth = None  # type: Optional[Tuple[str, str]]

        if self.configuration["auth_server"] == parts.netloc:
            auth = (self.configuration["auth_user"], self.configuration["auth_pswd"])

        try:
            if method == "get":
                req = requests.get(
                    url,
                    params=params,
                    proxies=proxies,
                    verify=ssl_cert_verif,
                    auth=auth,
                    timeout=30,
                )
            else:
                req = requests.post(
                    url,
                    data=params,
                    proxies=proxies,
                    verify=ssl_cert_verif,
                    auth=auth,
                    timeout=30,
                )
            ret = req.text.strip()
        except requests.exceptions.RequestException as ex:
            self.log.error(ex)

        self.log.debug("Content: %r", ret)
        return ret

    def runprocess(self, commandline, useshell=False):
        # type: (Union[str, List[str]], bool) -> str
        """ Runs a sub-process, wait for termination and returns
            the process output (both stdout and stderr, concatenated).

            Input: commandline : string or list of strings. First string is
                                 command, items are command-line options.
                   useshell: If true, system shell will be used to run the
                             program. Otherwise, the program will be run
                             directly with popen(). (Some program need to
                             have a full shell environment in order to run
                             properly.)

            Ouput; The output of the commande (stdout and stderr concatenated)
                   Empty string in case of failure.

            Example:
                print runprocess(['ifconfig','-a'])
                print runprocess('DISPLAY=:0 su %s -c "scrot %s"'
                                 % (user,filepath),useshell=True)
        """

        self.log.debug("%r & useshell=%r", commandline, useshell)
        try:
            myprocess = subprocess.Popen(
                commandline,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=useshell,
            )
            sout, serr = myprocess.communicate()
            myprocess.wait()
            if not sout:
                sout = b""
            if not serr:
                serr = b""
            else:
                # As you may think, here we should return something telling
                # that the command failed, but few tools on Windows use
                # STDERR to print useful informations, even if the commands
                # run as expected. So we need keep a track of the false
                # error (if any) and continue.
                self.log.error("STDERR: %s", serr.decode("utf-8"))

            if sys.version_info < (3,):
                # pylint: disable=undefined-variable
                return (
                    unicode(sout, ENCODING).encode("utf-8")  # noqa
                    + "\n"
                    + unicode(serr, ENCODING).encode("utf-8")  # noqa
                )

            return str("".join(map(chr, sout)) + "\n" + "".join(map(chr, serr)))
        except subprocess.CalledProcessError as ex:
            self.log.error("Process failed: %s", ex)

        return ""

    def screenshot(self, filename):
        # type: (str) -> List[str]
        """ Takes a screenshot and returns the path to the saved image
            (in TMP). None if could not take the screenshot.
        """
        files = []  # type: List[str]

        if not self.configuration["screenshot"]:
            self.log.info("Skipping screenshot.")
            return files

        self.log.info("Taking screenshot")
        if not self.user:
            self.log.error("Could not determine current user. Cannot take screenshot.")
            return files

        temp = gettempdir()
        filepath = "{}_screenshot-%d.png".format(os.path.join(temp, filename))

        kwargs = {}
        if LINUX and "DISPLAY" in os.environ:
            kwargs["display"] = os.getenv("DISPLAY")

        try:
            with mss.mss(**kwargs) as sct:
                for sct_file in sct.save(output=filepath):
                    self.log.debug(sct_file)
                    files.append(sct_file)
        except mss.ScreenShotError as ex:
            self.log.error(ex)

        return files

    def snapshot_sendto_server(self, filename, data):
        # type: (str, bytes) -> None
        """ Compute authentication token and send the report to all servers.
        """

        filedata = b64encode(data)
        key = str(self.configuration["password"]).encode()
        msg = str(str(filedata.decode()) + "***" + filename).encode()
        authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()

        # Send to the webserver (HTTP POST).
        parameters = {"filename": filename, "filedata": filedata, "token": authtoken}
        txt = "Sending file (%s) to %s"
        for distant in self.configuration["server_url"].split("|"):
            self.log.info(txt, sizeof_fmt(len(filedata)), urlsplit(distant).netloc)
            self.request_url(distant, "post", parameters)

    def snapshot(self, current_ip):
        # type: (str) -> None
        """ Make a global snapshot of the system (ip, screenshot, webcam...)
            and sends it to the internet.
            If not internet connexion is available, will exit.
        """

        # Note: when making a snapshot, we will try each and every type
        # of snapshot (screenshot, webcam, etc.)
        # If a particular snapshot fails, it will simply skip it.

        # Initialisations
        temp = gettempdir()
        report_name = platform.node() + time.strftime("_%Y%m%d_%H%M%S")

        # Create the system report (IP, date/hour...)
        self.log.info("Filename: %s", report_name)
        self.log.info("Collecting system info")
        filepath = "{}.txt".format(os.path.join(temp, report_name))
        with open(filepath, "w") as fileh:
            fileh.write(self.system_report(current_ip))
        filestozip = [filepath]

        # Take screenshot(s)
        filestozip.extend(self.screenshot(report_name))

        # Take a webcam snapshot
        webcam = self.webcamshot(report_name)
        if webcam:
            filestozip.append(webcam)

        # Zip files:
        self.log.info("Zipping files")
        os.chdir(temp)
        report_name += ".zip"
        output = os.path.join(temp, report_name)
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zip_:
            for filepath in filestozip:
                zip_.write(os.path.basename(filepath))

        # Remove temporary files.
        for filepath in filestozip:
            os.remove(filepath)

        # Encrypt using gpg with a specified public key
        dumb = "i_dont_wanna_use_encryption_and_i_assume"
        if self.configuration["gpgkeyid"] == dumb:
            # You shall not pass!
            self.log.info("Skipping encryption (bad, Bad, BAD ...)")
        else:
            self.log.info("Encrypting zip with GnuPG")
            if self.configuration["gpg_binary"] == "":
                self.log.critical("The path to the GPG binary is not set. Aborting.")
                sys.exit(1)

            self.runprocess(
                [
                    self.configuration["gpg_binary"],
                    "--batch",
                    "--no-default-keyring",
                    "--trust-model",
                    "always",
                    "-r",
                    self.configuration["gpgkeyid"],
                    "-o",
                    output + ".gpg",
                    "-e",
                    output,
                ]
            )

            # Delete the ZIP file
            os.remove(output)

            report_name += ".gpg"
            output += ".gpg"
            if not os.path.isfile(output):
                self.log.critical("GPG encryption failed. Aborting.")
                sys.exit(1)

        # Read the output file (either a ZIP or GPG file)
        with open(output, "rb") as filei:
            data = filei.read()

        # Send to all servers
        self.snapshot_sendto_server(report_name, data)

    def stolen(self):
        # type: () -> bool
        """ Returns True is the computer was stolen. """
        now = time.time()

        # Small filter to prevent spamming the server at every check on stolenness
        if (now - self.stolen_last_update) > 2:
            self.stolen_last_update = time.time()
            salt = "just check if I am a stolen one"
            key = str(self.configuration["password"]).encode()
            msg = str(salt + "***" + self.configuration["check_file"]).encode()
            authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()
            parameters = {
                "filename": self.configuration["check_file"],
                "filedata": salt,
                "verify": authtoken,
            }

            self.stolen_var = False

            for distant in self.configuration["server_url"].split("|"):
                self.log.info("Checking status on %s", urlsplit(distant).netloc)
                if self.request_url(distant, "post", parameters) == "1":
                    self.log.info("<<!>> Stolen computer <<!>>")
                    self.stolen_var = True

            if not self.stolen_var:
                self.log.info("Computer *does not* appear to be stolen.")

        return self.stolen_var

    def system_report(self, current_ip):
        # type: (str) -> str
        """ Returns a system report: computer name, date/time, public IP,
            list of wired and wireless interfaces and their configuration, etc.
        """

        separator = "\n" + 75 * "-"
        ver = sys.version_info
        version_ = "{0}.{1}.{2}".format(ver.major, ver.minor, ver.micro)
        self.log.debug("Using Python %s", version_)
        report_ = """Pombo {0} report {1}
Username : {2}
Computer : {3}
Serial/N : {4}
System   : {5} {1}
Public IP: {6} (approximate geolocation: http://www.geoiptool.com/?IP={6}) {1}
Date/time: {7} (local time) {1}
"""
        report = report_.format(
            __version__,
            separator,
            self.user,
            self.get_manufacturer(),
            self.get_serial(),
            " ".join(platform.uname()),
            current_ip,
            datetime.now(),
        )
        separator = "\n" + separator + "\n"

        # Primary commands, the Network stuff ...
        todo = [
            ("network_config", "Network config"),
            ("wifi_access_points", "Nearby wireless access points"),
            ("traceroute", "Network routes"),
            ("network_trafic", "Current network connections"),
        ]
        for key, info in todo:
            self.log.debug("System report: %s()", key)
            report += "{}:\n".format(info)
            if not self.configuration[key]:
                report += "Disabled."
            else:
                key_ = self.configuration[key].split(" ")
                informations = self.runprocess(key_)
                report += informations.strip()
            report += separator
        report += "Report end.\n"

        if self.is_windows():
            report = report.replace("\r\n", "\n")
        return report

    def webcamshot(self, filename):
        # type: (str) -> Union[str, None]
        """ Takes a snapshot with the webcam and returns the path to the
            saved image (in TMP). None if could not take the snapshot.
        """

        if not self.configuration["camshot"]:
            self.log.info("Skipping webcamshot.")
            return None

        temp = gettempdir()
        self.log.info("Taking webcamshot")
        if self.is_windows():
            filepath = "{}_webcam.jpg".format(os.path.join(temp, filename))
            try:
                cam = Device(devnum=0)  # type: ignore
                if not cam:
                    cam = Device(devnum=1)  # type: ignore
            except Exception as ex:  # pylint: disable=broad-except
                self.log.error("vidcap.Error: %s", ex)
                return None

            try:
                # Here you can modify the picture resolution
                # cam.setResolution(768, 576)
                cam.getImage()
                time.sleep(2)
                cam.saveSnapshot(filepath)
            except ValueError as ex:
                self.log.error(ex)
                return None
        else:
            filepath = "{}_webcam.{}".format(
                os.path.join(temp, filename), self.configuration["camshot_filetype"]
            )
            cmd = self.configuration["camshot"].replace("<filepath>", filepath)
            self.runprocess(cmd, useshell=True)
            if (
                os.path.isfile(filepath)
                and self.configuration["camshot_filetype"] == "ppm"
            ):
                full_path_ = os.path.join(temp, filename)
                new_path_ = "{}_webcam.jpg".format(full_path_)
                self.runprocess(["/usr/bin/convert", filepath, new_path_])
                os.unlink(filepath)
                filepath = new_path_

        if not os.path.isfile(filepath):
            return None

        self.log.debug(filepath)
        return filepath

    def work(self):
        # type: () -> None
        """ Primary function, it will launch the report based on the
            stolen state.
        """

        # pylint: disable=too-many-branches

        if not self.configuration:
            self.configuration = self.config()

        if self.testing:
            self.install_log_handlers(logging.DEBUG)
            self.log.info("[Test] Simulating stolen computer ...")
            current_ip = self.public_ip()
            if not current_ip:
                self.log.error("Test cannot continue ...")
                return

            self.snapshot(current_ip)
            wait_stolen = self.configuration["time_limit"] // 3
            if self.configuration["only_on_ip_change"]:
                complement = "on ip change"
            else:
                complement = "every {} minutes".format(self.configuration["time_limit"])
            self.log.info(
                (
                    "==> In real scenario, Pombo will send a report"
                    " every %d minutes if stolen, %s otherwise."
                ),
                wait_stolen,
                complement,
            )
            return

        if self.is_windows():
            # Cron job like for Windows :s
            while True:
                wait_normal = 60 * self.configuration["time_limit"]
                wait_stolen = wait_normal // 3
                current_ip = self.public_ip()
                report_needed, is_stolen = self.need_report(current_ip)
                if current_ip and report_needed:
                    start = time.time()
                    self.snapshot(current_ip)
                    runtime = time.time() - start
                if is_stolen:
                    time.sleep(wait_stolen - runtime)
                else:
                    time.sleep(wait_normal - runtime)
            return

        current_ip = self.public_ip()
        report_needed, is_stolen = self.need_report(current_ip)
        if current_ip and report_needed:
            wait = 60 * self.configuration["time_limit"] // 3
            if is_stolen:
                wait = 60
            for i in range(1, 4):
                self.log.info("* Attempt %d/3 *", i)
                start = time.time()
                self.snapshot(current_ip)
                runtime = time.time() - start
                if i < 3:
                    time.sleep(wait - runtime)


class PomboArg(object):
    """ CLI arguments traitment. """

    def parse(self, arg):
        # type: (str) -> int
        """ Handle CLI arguments. """

        # Backward-compatibility (renamed those methods in 1.1.0 to not conflict with builtins)
        if arg == "help":
            arg = "usage"
        elif arg == "list":
            arg = "list_ips"

        print("Pombo {}".format(__version__))
        try:
            return getattr(self, arg)()
        except AttributeError:
            printerr('Unknown argument "{}" - try "help".'.format(arg))

        return 1

    @staticmethod
    def add():
        # type: () -> int
        """ Add an IP to the ip_file if not already known. """

        pombo = Pombo()
        curr_ip = pombo.public_ip()
        if not curr_ip:
            return 1

        known = False
        if os.path.isfile(pombo.ip_file):
            # Read previous IP
            with open(pombo.ip_file) as fileh:
                previous_ips = fileh.readlines()
                if hash_string(curr_ip) in [s.strip() for s in previous_ips]:
                    print("IP already known.")
                    known = True

        if not known:
            print("Adding IP {} to {}".format(curr_ip, pombo.ip_file))
            with open(pombo.ip_file, "a+") as fileh:
                fileh.write(hash_string(curr_ip) + "\n")

        return 0

    @staticmethod
    def usage():
        # type: () -> int
        """ Print help message. """

        print("Options ---")
        print("   add      add the current IP to {}".format(Pombo.ip_file))
        print("   check    launch Pombo in verbose mode")
        print("   help     show this message")
        print("   list     list known IP")
        print("   update   check for update")
        print("   version  show Pombo, python and PIL versions")
        return 0

    @staticmethod
    def list_ips():
        # type: () -> int
        """ Print known IPs from ip_file. """

        if not os.path.isfile(Pombo.ip_file):
            print("There is no known IP address.")
        else:
            with open(Pombo.ip_file) as fileh:
                print("IP hashes in {}:".format(Pombo.ip_file))
                for ip_h in fileh.readlines():
                    print("   {}...{}".format(ip_h[:20], ip_h.strip()[-20:]))

        return 0

    @staticmethod
    def update():
        # type: () -> int
        """ Check for a newer version. """

        try:
            req = requests.get(UPLINK, verify=True)
        except requests.exceptions.RequestException as ex:
            print(" ! Arf, check failed: {}!".format(ex))
            print(" . Please check later.")
            return 1

        version = StrictVersion(req.text.strip())
        current_version = StrictVersion(__version__)

        if version > current_version:
            if version.prerelease:
                print(" - Development version available: {}".format(version))
                print(" . You should upgrade only for tests purpose!")
                print(" - Check {}".format(URL))
                print("   and report issues/ideas on GitHub")
            else:
                print(" + Yep! New version is available: {}".format(version))
                print(" - Check {} for upgrade.".format(URL))
        elif version < current_version:
            print("Ouhou! It seems that you are in advance on your time ;)")
        else:
            print("Version is up to date!")

        return 0

    @staticmethod
    def version():
        # type: () -> int
        """ Print Pombo and modules versions. """

        ver = sys.version_info
        print("I am using Python {}.{}.{}".format(ver.major, ver.minor, ver.micro))
        print("            & MSS {}".format(mss.__version__))
        print("            & IPy {}".format(IPy.__version__))
        print("        & request {}".format(requests.__version__))
        if WINDOWS:
            print("   & VideoCapture {}".format(VC_VERSION))
            print("            & PIL {}".format(Image.VERSION))  # type: ignore

        return 0


def main(args):
    # type: (List[str]) -> int
    """ Usage example. """

    ret = 0

    try:
        if args and args[0] != "check":
            parser = PomboArg()
            ret = parser.parse(args[0])
        else:
            pombo = Pombo(testing="check" in args)
            pombo.work()
    except KeyboardInterrupt:
        printerr("*** STOPPING operations ***")
        ret = 1
    except Exception as ex:
        printerr(str(ex))
        raise

    return ret


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    sys.exit(main(sys.argv[1:]))
