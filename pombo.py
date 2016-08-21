#!/usr/bin/env python
# coding: utf-8
'''
Pombo
Theft-recovery tracking opensource software
http://pombo.jmsinfo.co
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
'''

from __future__ import print_function

__version__ = '1.0.3'
__author__ = 'JMSinfo'
__date__ = '$18-May-2015 14:28:57$'

import hashlib
import hmac
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
from locale import getdefaultlocale
from tempfile import gettempdir

try:
    from ConfigParser import Error, SafeConfigParser
except ImportError:
    from configparser import Error, SafeConfigParser

try:
    import requests
    from requests.exceptions import ConnectionError, RequestException
    from IPy import IP
    if os.name == 'nt':
        from PIL import Image
        from VideoCapture import Device
        from mss import mss, ScreenshotError
except ImportError as ex:
    print(ex)
    sys.exit(1)


# ----------------------------------------------------------------------
# --- [ Routines ] -----------------------------------------------------
# ----------------------------------------------------------------------
def file_size(filename):
    ''' Get file to send size. '''

    num = os.path.getsize(filename)
    for key in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0 and num > -1024.0:
            return '{0:3.1f}{1}'.format(num, key)
        num /= 1024.0
    return '{0:3.1f}{1}'.format(num, 'TB')


def hash_string(current_ip):
    ''' IP hash method - could be easily modifed. '''

    return hashlib.sha256(current_ip.encode()).hexdigest()


def printerr(string=''):
    ''' Print an error message to STDERR. '''

    sys.stderr.write(str(string) + "\n")


def to_bool(value=''):
    ''' Return a boolean of a given string. '''

    return str(value).lower() in {'true', 'on', '1', 'yes', 'oui'}


# ----------------------------------------------------------------------
# --- [ Classes ] ------------------------------------------------------
# ----------------------------------------------------------------------
class Pombo(object):
    ''' Pombo core. '''

    url = 'https://github.com/BoboTiG/pombo'
    uplink = 'https://raw.github.com/BoboTiG/pombo/master/VERSION'
    os_name = ''
    conf = '/etc/pombo.conf'
    ip_file = '/var/local/pombo'
    log_file = '/var/log/pombo.log'
    encoding = sys.stdin.encoding or getdefaultlocale()[1] or 'utf-8'
    user = None
    log = None
    testing = False
    configuration = {}
    vc_version = '0.9.5'

    def __init__(self, testing=False):
        ''' Pombo initializations. '''

        try:
            oses_ = {'Linux': 'Linux', 'Darwin': 'Mac', 'Windows': 'Windows'}
            self.os_name = oses_[platform.system()]
        except KeyError:
            print("System '{0}' not implemented.".format(platform.system()))
            sys.exit(1)

        if self.os_name == 'Windows':
            self.ip_file = 'c:\\pombo\\pombo'
            self.conf = 'c:\\pombo\\pombo.conf'
            self.log_file = os.path.join(gettempdir(), 'pombo.log')

        self.testing = bool(testing)
        self.log = logging.getLogger()
        self.user = self.current_user()
        self.install_log_handlers()

    def __del__(self):
        ''' Actions to do when Pombo class is destroyed. '''

        if self.log:
            self.log.info('Session terminated.')

    def config(self):
        ''' Get configuration from conf file. '''

        if not os.path.isfile(self.conf):
            printerr("[Errno 2] No such file or directory: '{}'"
                     .format(self.conf))
            sys.exit(1)
        if not os.access(self.conf, os.R_OK):
            printerr("[Errno 13] Permission denied: '{}'".format(self.conf))
            sys.exit(1)

        self.log.debug('Loading configuration')
        defaults = {
            'gpgkeyid': None,
            'password': None,
            'server_url': None,
            'check_file': None,
            'time_limit': 15,
            'email_id': '',
            'only_on_ip_change': False,
            'enable_log': False,
            'use_proxy': False,
            'use_env': False,
            'http_proxy': '',
            'https_proxy': '',
            'auth_server': '',
            'auth_user': '',
            'auth_pswd': '',
            'gpg_binary': '',
            'network_config': '',
            'wifi_access_points': '',
            'traceroute': '',
            'network_trafic': '',
            'screenshot': '',
            'camshot': '',
            'camshot_filetype': ''
        }
        config = {}
        try:
            conf = SafeConfigParser(defaults=defaults)
            conf.read(self.conf)
        except Error as ex:
            self.log.error(ex)
            sys.exit(1)

        # Primary parameters
        config['gpgkeyid'] = conf.get('General', 'gpgkeyid')
        config['password'] = conf.get('General', 'password')
        config['server_url'] = conf.get('General', 'server_url')
        config['check_file'] = conf.get('General', 'check_file')
        config['time_limit'] = conf.getint('General', 'time_limit')
        error = False
        for key in config:
            if not config[key]:
                self.log.error('config error: empty %s parameter.', key)
                error = True
        if error:
            self.log.critical('Pombo has to stop, please check parameters.')
            sys.exit(0)

        # Secondary parameters (auth., email, commands, ...)
        config['email_id'] = conf.get('General', 'email_id')
        config['only_on_ip_change'] = conf.getboolean('General',
                                                      'only_on_ip_change')
        config['enable_log'] = conf.getboolean('General', 'enable_log')
        config['use_proxy'] = conf.getboolean('General', 'use_proxy')
        config['use_env'] = conf.getboolean('General', 'use_env')
        config['http_proxy'] = conf.get('General', 'http_proxy')
        config['https_proxy'] = conf.get('General', 'https_proxy')
        config['auth_server'] = conf.get('General', 'auth_server')
        config['auth_user'] = conf.get('General', 'auth_user')
        config['auth_pswd'] = conf.get('General', 'auth_pswd')
        config['gpg_binary'] = conf.get('Commands', 'gpg_binary')
        config['network_config'] = conf.get('Commands', 'network_config')
        config['wifi_access_points'] = conf.get('Commands',
                                                'wifi_access_points')
        config['traceroute'] = conf.get('Commands', 'traceroute')
        config['network_trafic'] = conf.get('Commands', 'network_trafic')
        config['screenshot'] = conf.get('Commands', 'screenshot')
        config['camshot'] = conf.get('Commands', 'camshot')
        config['camshot_filetype'] = conf.get('Commands', 'camshot_filetype')

        # Informations logging
        if not config['enable_log']:
            self.log.debug('Disabling console logger')
            del self.log.handlers[1]

        return config

    def current_user(self):
        ''' Return the user who is currently logged in and uses the X
            session. None if could not be determined.
        '''

        user = None
        if self.os_name == 'Windows':
            user = self.runprocess(['echo', '%userNAME%'], useshell=True)
        else:
            lines_ = self.runprocess(['who', '-s'], useshell=True).split('\n')
            for line in lines_:
                if 'tty' in line or 'pts' in line:
                    user = line.split(' ')[0]
                    if '(:0)' in line:
                        break
            user = user.strip()
        self.log.debug('Username is %s', user)
        return user

    def get_manufacturer(self):
        ''' Get the manufacturer. '''

        if self.os_name == 'Windows':
            cmd = 'wmic csproduct get vendor, name, version /value'
            res = self.runprocess(cmd, useshell=True).strip().split("\r\n")
            if len(res) < 3:
                manufacturer = 'Unknown'
            else:
                manufacturer = res[1].split('=')[1].strip() + ' - ' + \
                    res[0].split('=')[1].strip() + ' - ' + \
                    res[2].split('=')[1].strip()
        elif self.os_name == 'Mac':
            cmd = '/usr/sbin/system_profiler SPHardwareDataType | grep Model'
            res = self.runprocess(cmd, useshell=True).strip().split("\n")
            manufacturer = res[0].split(': ')[1].strip() + ' - ' + \
                res[1].split(': ')[1].strip()
        else:
            manufacturer = ''
            for info in ['system-manufacturer', 'system-product-name',
                         'system-version']:
                cmd = '/usr/sbin/dmidecode --string ' + info
                res = self.runprocess(cmd, useshell=True).strip()
                manufacturer += res + ' - '
            manufacturer = manufacturer[:-3]
        self.log.debug('Manufacturer is %s', manufacturer)
        return manufacturer

    def get_serial(self):
        ''' Get the serial number. '''

        serial = 'Unknown'
        cmd = {
            'Linux': '/usr/sbin/dmidecode --string system-serial-number',
            'Mac': '/usr/sbin/system_profiler SPHardwareDataType ' +
            '| grep system | cut -d: -f2',
            'Windows': 'wmic bios get serialnumber /value'
        }
        res = self.runprocess(cmd[self.os_name], useshell=True).strip()
        if self.os_name == 'Windows':
            res = res.split('=')
            if not res[0][0:3] == 'ERR' and not res[1] == '0':
                serial = res[1]
        else:
            if not res == 'System Serial Number':
                serial = res
        self.log.debug('Serial number is %s', serial)
        return serial

    def install_log_handlers(self, level=logging.INFO):
        ''' Install log handlers: one for the file log_file and one for
            the console.
        '''

        self.log.handlers = []
        self.log.setLevel(level)
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(funcName)s::L%(lineno)d %(message)s')

        # Log to file
        try:
            file_handler = logging.FileHandler(self.log_file, 'a')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.log.addHandler(file_handler)
            self.log.debug('Log file is %s', self.log_file)
        except IOError as ex:
            printerr(ex)

        # Log to console
        steam_handler = logging.StreamHandler()
        steam_handler.setLevel(level)
        self.log.addHandler(steam_handler)

    def ip_changed(self, curr_ip):
        ''' Check if current_ip is already known from ip_file. '''

        if self.configuration['only_on_ip_change']:
            # Read previous IP
            if not os.path.isfile(self.ip_file):
                txt_ = 'First run, writing down IP in "%s".'
                self.log.info(txt_, self.ip_file)
                with open(self.ip_file, 'w+') as fileh:
                    fileh.write(hash_string(curr_ip))
                return True
            else:
                with open(self.ip_file, 'r') as fileh:
                    prev_ips = fileh.readlines()
                if not hash_string(curr_ip) in [ip.strip() for ip in prev_ips]:
                    self.log.info('IP has changed.')
                    return True
                self.log.info('IP has not changed. Aborting.')
        else:
            self.log.info('Skipping check based on IP change.')
        return False

    def need_report(self, current_ip):
        ''' Return the stolen state or the computer IP.
            If one of them is True, so we need to send a report.
        '''

        return self.stolen() or self.ip_changed(current_ip)

    def public_ip(self):
        ''' Returns your public IP address.
            Output: The IP address in string format.
                    None if not internet connection is available.
        '''

        if not self.configuration:
            self.configuration = self.config()

        for distant in self.configuration['server_url'].split('|'):
            txt_ = 'Retrieving IP address from %s'
            self.log.info(txt_, distant.split('/')[2])
            try:
                current_ip = self.request_url(distant, 'get', {'myip': '1'})
                IP(current_ip)
            except (gaierror, ValueError) as ex:
                self.log.error(ex)
                return None
            return current_ip

        # Make sure we are connected to the internet:
        # (If the computer has no connexion to the internet, it's no use
        # accumulating snapshots.)
        if not current_ip:
            self.log.error(
                'Computer does not seem to be connected to the internet. Aborting.')
        return None

    def request_url(self, url, method='get', params=None):
        ''' Make a request with all options "aux petits oignons".
        '''

        # Proxies
        proxies = {}
        if self.configuration['use_proxy']:
            if self.configuration['use_env']:
                proxies['http'] = os.getenv('http_proxy')
                proxies['https'] = os.getenv('https_proxy')
            else:
                proxies['http'] = self.configuration['http_proxy']
                proxies['https'] = self.configuration['https_proxy']

        ret = str('')
        ssl_cert_verif = url.split(':') == 'https'
        auth = ()

        if self.configuration['auth_server'] == url.split('/')[2]:
            auth = (self.configuration['auth_user'],
                    self.configuration['auth_pswd'])
        try:
            if method == 'get':
                req = requests.get(url,
                                   params=params,
                                   proxies=proxies,
                                   verify=ssl_cert_verif,
                                   auth=auth,
                                   timeout=30)
            else:
                req = requests.post(url,
                                    data=params,
                                    proxies=proxies,
                                    verify=ssl_cert_verif,
                                    auth=auth,
                                    timeout=30)
            ret = req.content.strip().decode()
        except RequestException as ex:
            self.log.error(ex)
        self.log.debug('Content: %s', ret)
        return ret

    def runprocess(self, commandline, useshell=False):
        ''' Runs a sub-process, wait for termination and returns
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
        '''

        self.log.debug('{} & useshell={}'.format(commandline, useshell))
        try:
            myprocess = subprocess.Popen(commandline,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         shell=useshell)
            (sout, serr) = myprocess.communicate()
            myprocess.wait()
            if not sout:
                sout = ''
            if not serr:
                serr = ''
            else:
                # As you may think, here we should return something telling
                # that the command failed, but few tools on Windows use
                # STDERR to print useful informations, even if the commands
                # run as expected. So we need keep a track of the false
                # error (if any) and continue.
                self.log.error('STDERR: %s', serr)
            if sys.version > '3':
                return str(
                    ''.join(map(chr, sout)) + "\n" + ''.join(map(chr, serr)))
            else:
                return unicode(sout, self.encoding).encode('utf-8') + \
                    "\n" + unicode(serr, self.encoding).encode('utf-8')
        except subprocess.CalledProcessError as ex:
            self.log.error('Process failed: %s', ex)
        return ''

    def screenshot(self, filename):
        ''' Takes a screenshot and returns the path to the saved image
            (in TMP). None if could not take the screenshot.
        '''

        if not self.configuration['screenshot']:
            self.log.info('Skipping screenshot.')
            return None

        temp = gettempdir()
        self.log.info('Taking screenshot')
        filepath = '{}_screenshot'.format(os.path.join(temp, filename))
        if not self.user:
            self.log.error(
                'Could not determine current user. Cannot take screenshot.')
            return None

        if self.os_name == 'Windows':
            try:
                img = mss()
                filepath = next(img.save(output=filepath, screen=-1))
            except (ValueError, ScreenshotError) as ex:
                self.log.error(ex)
        else:
            filepath += '.jpg'
            cmd = self.configuration['screenshot']
            cmd = cmd.replace('<user>', self.user)
            cmd = cmd.replace('<filepath>', filepath)
            self.runprocess(cmd, useshell=True)
        if not os.path.isfile(filepath):
            return None
        return filepath

    def snapshot_sendto_server(self, filename, filepath, data):
        ''' Compute authentication token and send the report to all servers.
        '''

        filedata = b64encode(data)
        filesize = file_size(filepath)
        os.remove(filepath)
        key = self.configuration['password']
        if sys.version > '3':
            key = key.encode()
            msg = str(filedata.decode()) + '***' + filename
            msg = msg.encode()
        else:
            msg = filedata + '***' + filename
        authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()

        # Send to the webserver (HTTP POST).
        parameters = {
            'filename': filename,
            'filedata': filedata,
            'token': authtoken
        }
        for distant in self.configuration['server_url'].split('|'):
            txt_ = 'Sending file (%s) to %s'
            self.log.info(txt_, filesize, distant.split('/')[2])
            self.request_url(distant, 'post', parameters)
        return

    def snapshot(self, current_ip):
        ''' Make a global snapshot of the system (ip, screenshot, webcam...)
            and sends it to the internet.
            If not internet connexion is available, will exit.
        '''

        # Note: when making a snapshot, we will try each and every type
        # of snapshot (screenshot, webcam, etc.)
        # If a particular snapshot fails, it will simply skip it.

        # Initialisations
        temp = gettempdir()
        report_name = platform.node() + time.strftime('_%Y%m%d_%H%M%S')

        # Create the system report (IP, date/hour...)
        self.log.info('Filename: %s', report_name)
        self.log.info('Collecting system info')
        filepath = '{}.txt'.format(os.path.join(temp, report_name))
        with open(filepath, 'a') as fileh:
            fileh.write(self.system_report(current_ip))
        filestozip = []
        filestozip.append(filepath)

        # Take a screenshot
        screen = self.screenshot(report_name)
        if screen:
            filestozip.append(screen)

        # Take a webcam snapshot
        webcam = self.webcamshot(report_name)
        if webcam:
            filestozip.append(webcam)

        # Zip files:
        self.log.info('Zipping files')
        os.chdir(temp)
        zipfilepath = '{}.zip'.format(os.path.join(temp, report_name))
        fileh = zipfile.ZipFile(zipfilepath, 'w', zipfile.ZIP_DEFLATED)
        for filepath in filestozip:
            fileh.write(os.path.basename(filepath))
        fileh.close()

        # Remove temporary files.
        for filepath in filestozip:
            os.remove(filepath)

        # Encrypt using gpg with a specified public key
        gpgfilepath = zipfilepath
        dumb_ = 'i_dont_wanna_use_encryption_and_i_assume'
        if self.configuration['gpgkeyid'] == dumb_:
            # You shall not pass!
            self.log.info('Skipping encryption (bad, Bad, BAD ...)')
            os.rename(zipfilepath, gpgfilepath)
        else:
            self.log.info('Encrypting zip with GnuPG')
            if self.configuration['gpg_binary'] == '':
                self.log.critical(
                    'The path to the GPG binary is not set. Aborting.')
                sys.exit(1)
            gpgfilepath += '.gpg'
            self.runprocess([self.configuration['gpg_binary'], '--batch',
                             '--no-default-keyring', '--trust-model', 'always',
                             '-r', self.configuration['gpgkeyid'], '-o',
                             gpgfilepath, '-e', zipfilepath])
            os.remove(zipfilepath)
            if not os.path.isfile(gpgfilepath):
                self.log.critical('GPG encryption failed. Aborting.')
                sys.exit(1)

        # Read GPG file
        with open(gpgfilepath, 'r+b') as fileh:
            data = fileh.read()
        gpgfilename = os.path.basename(gpgfilepath)

        # Send to all servers
        self.snapshot_sendto_server(gpgfilename, gpgfilepath, data)
        return

    def stolen(self):
        ''' Returns True is the computer was stolen. '''

        salt = 'just check if I am a stolen one'
        key = self.configuration['password']
        msg = salt + '***' + self.configuration['check_file']
        if sys.version > '3':
            key = key.encode()
            msg = msg.encode()
        authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()
        parameters = {
            'filename': self.configuration['check_file'],
            'filedata': salt,
            'verify': authtoken
        }
        for distant in self.configuration['server_url'].split('|'):
            self.log.info('Checking status on %s', distant.split('/')[2])
            if self.request_url(distant, 'post', parameters) == '1':
                self.log.info('<<!>> Stolen computer <<!>>')
                return True
        self.log.info('Computer *does not* appear to be stolen.')
        return False

    def system_report(self, current_ip):
        ''' Returns a system report: computer name, date/time, public IP,
            list of wired and wireless interfaces and their configuration, etc.
        '''

        separator = "\n" + 75 * '-'
        ver = sys.version_info
        version_ = '{0}.{1}.{2}'.format(ver.major, ver.minor, ver.micro)
        self.log.debug('Using Python %s', version_)
        report_ = """Pombo {0} report {1}
Username : {2}
Computer : {3}
Serial/N : {4}
System   : {5} {1}
Public IP: {6} (approximate geolocation: http://www.geoiptool.com/?IP={6}) {1}
Date/time: {7} (local time) {1}
"""
        report = report_.format(__version__, separator, self.user,
                                self.get_manufacturer(), self.get_serial(),
                                ' '.join(platform.uname()), current_ip,
                                datetime.now())
        separator = "\n" + separator + "\n"

        # Primary commands, the Network stuff ...
        todo = [('network_config', 'Network config'),
                ('wifi_access_points', 'Nearby wireless access points'),
                ('traceroute', 'Network routes'),
                ('network_trafic', 'Current network connections')]
        for key, info in todo:
            self.log.debug('System report: %s()', key)
            report += "{}:\n".format(info)
            if not self.configuration[key]:
                report += 'Disabled.'
            else:
                key_ = self.configuration[key].split(' ')
                informations = self.runprocess(key_)
                report += informations.strip()
            report += separator
        report += "Report end.\n"

        if self.os_name == 'Windows':
            report = report.replace("\r\n", "\n")
        return report

    def webcamshot(self, filename):
        ''' Takes a snapshot with the webcam and returns the path to the
            saved image (in TMP). None if could not take the snapshot.
        '''

        if not self.configuration['camshot']:
            self.log.info('Skipping webcamshot.')
            return None

        temp = gettempdir()
        self.log.info('Taking webcamshot')
        if self.os_name == 'Windows':
            filepath = '{}_webcam.jpg'.format(os.path.join(temp, filename))
            try:
                cam = Device(devnum=0)
                if not cam:
                    cam = Device(devnum=1)
            except Exception as ex:
                self.log.error('vidcap.Error: %s', ex)
                return None
            try:
                # Here you can modify the picture resolution
                # cam.setResolution(768, 576)
                cam.getImage()
                time.sleep(1)
                cam.saveSnapshot(filepath)
            except ValueError as ex:
                self.log.error(ex)
                return None
        else:
            filepath = '{}_webcam.{}'.format(
                os.path.join(temp, filename),
                self.configuration['camshot_filetype'])
            cmd = self.configuration['camshot'].replace('<filepath>', filepath)
            self.runprocess(cmd, useshell=True)
            if os.path.isfile(filepath):
                if self.configuration['camshot_filetype'] == 'ppm':
                    full_path_ = os.path.join(temp, filename)
                    new_path_ = '{}_webcam.jpg'.format(full_path_)
                    self.runprocess(['/usr/bin/convert', filepath, new_path_])
                    os.unlink(filepath)
                    filepath = new_path_
        if not os.path.isfile(filepath):
            return None
        return filepath

    def work(self):
        ''' Primary function, it will launch the report based on the
            stolen state.
        '''

        if not self.configuration:
            self.configuration = self.config()

        if self.testing:
            self.install_log_handlers(logging.DEBUG)
            self.log.info('[Test] Simulating stolen computer ...')
            current_ip = self.public_ip()
            if current_ip is None:
                self.log.error('Test cannot continue ...')
                return
            self.snapshot(current_ip)
            wait_stolen = self.configuration['time_limit'] // 3
            self.log.info('==> In real scenario, Pombo will send a report' +
                          ' each {} minutes.'.format(wait_stolen))
        else:
            if self.os_name == 'Windows':
                # Cron job like for Windows :s
                while True:
                    wait_normal = 60 * self.configuration['time_limit']
                    wait_stolen = wait_normal // 3
                    current_ip = self.public_ip()
                    if current_ip and self.need_report(current_ip):
                        start = time.time()
                        self.snapshot(current_ip)
                        runtime = time.time() - start
                        time.sleep(wait_stolen - runtime)
                    else:
                        time.sleep(wait_normal)
            else:
                current_ip = self.public_ip()
                if current_ip and self.need_report(current_ip):
                    wait = 60 * self.configuration['time_limit'] // 3
                    for i in range(1, 4):
                        self.log.info('* Attempt %d/3 *', i)
                        start = time.time()
                        self.snapshot(current_ip)
                        runtime = time.time() - start
                        if i < 3:
                            time.sleep(wait - runtime)


class PomboArg(object):
    ''' CLI arguments traitment. '''

    def __init__(self, arg=None):
        '''
        '''

        if arg and hasattr(self, arg):
            getattr(self, arg)()
        else:
            printerr('Unknown argument "{}" - try "help".'.format(arg))

    def add(self):
        ''' Add an IP to the ip_file if not already known. '''

        pombo = Pombo()
        curr_ip = pombo.public_ip()
        if not curr_ip:
            return
        known = False
        if os.path.isfile(pombo.ip_file):
            # Read previous IP
            with open(pombo.ip_file, 'r') as fileh:
                previous_ips = fileh.readlines()
                if hash_string(curr_ip) in [s.strip() for s in previous_ips]:
                    print('IP already known.')
                    known = True
        if not known:
            print('Adding IP {} to {}'.format(curr_ip, pombo.ip_file))
            with open(pombo.ip_file, 'a+') as fileh:
                fileh.write(hash_string(curr_ip) + "\n")

    def help(self):
        ''' Print help message. '''

        print('Options ---')
        print('   add      add the current IP to {}'.format(Pombo.ip_file))
        print('   check    launch Pombo in verbose mode')
        print('   help     show this message')
        print('   list     list known IP')
        print('   update   check for update')
        print('   version  show Pombo, python and PIL versions')

    def list(self):
        ''' Print known IPs from ip_file. '''

        if not os.path.isfile(Pombo.ip_file):
            print('There is no known IP address.')
        else:
            with open(Pombo.ip_file, 'r') as fileh:
                print('IP hashes in {}:'.format(Pombo.ip_file))
                for ip_h in fileh.readlines():
                    print('   {}...{}'.format(ip_h[:20], ip_h.strip()[-20:]))

    def update(self):
        ''' Check for a newer version. '''

        version = ''
        try:
            req = requests.get(Pombo.uplink, verify=True)
        except ConnectionError as ex:
            print(' ! Arf, check failed: {} !'.format(ex))
            print(' . Please check later.')
            return
        version = req.content.strip().decode()
        if version > __version__:
            if 'a' in version or 'b' in version:
                print(' - Development version available: {}'.format(version))
                print(' . You should upgrade only for tests purpose!')
                print(' - Check {}'.format(Pombo.url))
                print('   and report issues/ideas on GitHub')
            else:
                print(' + Yep! New version is available: {}'.format(version))
                print(' - Check {} for upgrade.'.format(Pombo.url))
        elif version < __version__:
            print('Ouhou! It seems that you are in advance on your time ;)')
        else:
            print('Version is up to date!')

    def version(self):
        ''' Print Pombo and modules versions. '''

        ver = sys.version_info
        print('I am using Python {}.{}.{}'.format(ver.major, ver.minor,
                                                  ver.micro))
        if platform.system() == 'Windows':
            print('with VideoCapture {}'.format(Pombo.vc_version))
            print('            & MSS {}'.format(mss.__version__))
            print('            & PIL {}'.format(Image.VERSION))


def main(argz):
    ''' Usage example. '''

    print('Pombo {}'.format(__version__))
    try:
        if len(argz) > 1 and argz[1] != 'check':
            PomboArg(argz[1])
        else:
            pombo = Pombo(testing='check' in argz)
            pombo.work()
    except KeyboardInterrupt:
        printerr('*** STOPPING operations ***')
        return 1
    except Exception as ex:
        printerr(ex)
        raise
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
