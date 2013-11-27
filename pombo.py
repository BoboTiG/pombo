#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Pombo
Theft-recovery tracking opensource software
http://bobotig.fr/?c=projets/pombo
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


Code quality check:
    pylint pombo.py
    coverage run pombo.py check
    coverage html
    (open htmlcov/index.html)
'''


__version__ = '0.0.11-a7'
__author__  = 'BoboTiG'
__date__    = '$26-Nov-2013 14:04:57$'


import base64
import datetime
import hashlib
import hmac
import locale
import logging
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import zipfile

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

try:
    import requests
    from requests.exceptions import ConnectionError, RequestException
    from IPy import IP
    if os.name == 'nt':
        from PIL import Image
        from VideoCapture import Device
        import mss
except ImportError as ex:
    print(ex)
    sys.exit(1)


# ----------------------------------------------------------------------
# --- [ Variables ] ----------------------------------------------------
# ----------------------------------------------------------------------

# Links
URL = 'https://github.com/BoboTiG/pombo'
UPLINK = 'https://raw.github.com/BoboTiG/pombo/master/VERSION'

# Current running OS specifities
try:
    _OSES = {'Linux': 'Linux', 'Darwin': 'Mac', 'Windows': 'Windows'}
    OS = _OSES[platform.system()]
except KeyError:
    print('System not implemented.')
    sys.exit(1)
CONF    = '/etc/pombo.conf'
IPFILE  = '/var/local/pombo'
LOGFILE = '/var/log/pombo.log'
if os.name == 'nt':
    IPFILE  = 'c:\\pombo\\pombo'
    CONF    = 'c:\\pombo\\pombo.conf'
    LOGFILE = os.path.join(tempfile.gettempdir(), 'pombo.log')
    VCVERSION = '0.9.5'

# Console encoding
ENCODING = sys.stdin.encoding or locale.getdefaultlocale()[1]
if not ENCODING:
    ENCODING = 'utf-8'

USER    = None
LOG     = None
CONFIG  = {}
PROXIES = {}


# ----------------------------------------------------------------------
# --- [ Functions ] ----------------------------------------------------
# ----------------------------------------------------------------------

def config():
    '''
        Get configuration from CONF file.
    '''

    LOG.info('Loading configuration')
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
    try:
        conf = ConfigParser.SafeConfigParser()
        conf.read(CONF)
    except ConfigParser.Error as ex:
        LOG.exception(ex)
        sys.exit(1)

    # Primary parameters
    CONFIG['gpgkeyid'] = conf.get('General', 'gpgkeyid')
    CONFIG['password'] = conf.get('General', 'password')
    CONFIG['server_url'] = conf.get('General', 'server_url')
    CONFIG['check_file'] = conf.get('General', 'check_file')
    CONFIG['time_limit'] = conf.getint('General', 'time_limit')
    error = False
    for key in CONFIG:
        if not CONFIG[key]:
            LOG.error('Config error: empty %s parameter.', key)
            error = True
    if error:
        LOG.critical('Pombo has to stop, please check parameters.')
        sys.exit(0)

    # Secondary parameters (auth., email, commands, ...)
    CONFIG['email_id'] = conf.get('General', 'email_id')
    CONFIG['only_on_ip_change'] = conf.getboolean('General', 'only_on_ip_change')
    CONFIG['enable_log'] = conf.getboolean('General', 'enable_log')
    CONFIG['use_proxy'] = conf.getboolean('General', 'use_proxy')
    CONFIG['use_env'] = conf.getboolean('General', 'use_env')
    CONFIG['http_proxy'] = conf.get('General', 'http_proxy')
    CONFIG['https_proxy'] = conf.get('General', 'https_proxy')
    CONFIG['auth_server'] = conf.get('General', 'auth_server')
    CONFIG['auth_user'] = conf.get('General', 'auth_user')
    CONFIG['auth_pswd'] = conf.get('General', 'auth_pswd')
    CONFIG['gpg_binary'] = conf.get('Commands', 'gpg_binary')
    CONFIG['network_config'] = conf.get('Commands', 'network_config')
    CONFIG['wifi_access_points'] = conf.get('Commands', 'wifi_access_points')
    CONFIG['traceroute'] = conf.get('Commands', 'traceroute')
    CONFIG['network_trafic'] = conf.get('Commands', 'network_trafic')
    CONFIG['screenshot'] = conf.get('Commands', 'screenshot')
    CONFIG['camshot'] = conf.get('Commands', 'camshot')
    CONFIG['camshot_filetype'] = conf.get('Commands', 'camshot_filetype')

    # Proxies
    if CONFIG['use_proxy']:
        if CONFIG['use_env']:
            PROXIES['http'] = os.getenv('http_proxy')
            PROXIES['https'] = os.getenv('https_proxy')
        else:
            PROXIES['http'] = CONFIG['http_proxy']
            PROXIES['https'] = CONFIG['https_proxy']

    # Informations logging
    if not CONFIG['enable_log']:
        LOG.info('Disabling console logger')
        del LOG.handlers[1]


def current_user():
    '''
        Return the user who is currently logged in and uses the X
        session. None if could not be determined.
    '''

    user = None
    if OS == 'Windows':
        user = runprocess(['echo', '%USERNAME%'], useshell=True)
    else:
        for line in runprocess(['who','-s'], useshell=True).split('\n'):
            if 'tty' in line:
                user = line.split(' ')[0]
                if '(:0)' in line:
                    break
    user = user.strip()
    LOG.debug('Username is %s', user)
    return user


def get_manufacturer():
    '''
        Get the manufacturer.
    '''

    if OS == 'Windows':
        cmd = 'wmic csproduct get vendor, name, version /value'
        res = runprocess(cmd, useshell=True).strip().split("\r\n")
        if len(res) < 3:
            manufacturer = 'Unknown'
        else:
            manufacturer  = res[1].split('=')[1].strip() + ' - '
            manufacturer += res[0].split('=')[1].strip() + ' - '
            manufacturer += res[2].split('=')[1].strip()
    elif OS == 'Mac':
        cmd = '/usr/sbin/system_profiler SPHardwareDataType | grep Model'
        res = runprocess(cmd, useshell=True).strip().split("\n")
        manufacturer  = res[0].split(': ')[1].strip() + ' - '
        manufacturer += res[1].split(': ')[1].strip()
    else:
        manufacturer = ''
        for info in [
            'system-manufacturer',
            'system-product-name',
            'system-version'
        ]:
            cmd = '/usr/sbin/dmidecode --string ' + info
            res = runprocess(cmd, useshell=True).strip()
            manufacturer += res + ' - '
        manufacturer = manufacturer[:-3]
    LOG.debug('Manufacturer is %s', manufacturer)
    return manufacturer


def get_serial():
    '''
        Get the serial number.
    '''

    serial = 'Unknown'
    cmd = {
        'Linux': '/usr/sbin/dmidecode --string system-serial-number',
        'Mac': '/usr/sbin/system_profiler SPHardwareDataType '
            +  '| grep system | cut -d: -f2',
        'Windows': 'wmic bios get serialnumber /value'
    }
    res = runprocess(cmd[OS], useshell=True).strip()
    if OS == 'Windows':
        res = res.split('=')
        if not res[0][0:3] == 'ERR' and not res[1] == '0':
            serial = res[1]
    else:
        if not res == 'System Serial Number':
            serial = res
    LOG.debug('Serial number is %s', serial)
    return serial


def file_size(filename):
    '''
        Get file to send size.
    '''

    num = os.path.getsize(filename)
    for key in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0 and num > -1024.0:
            return '{0:3.1f}{1}'.format(num, key)
        num /= 1024.0
    return '{0:3.1f}{1}'.format(num, 'TB')


def hash_string(current_ip):
    '''
        IP hash methods - could be easily modifed.
    '''

    return hashlib.sha256(current_ip.encode()).hexdigest()


def install_log_handlers(level=logging.DEBUG):
    '''
        Install LOG handlers: one for the file LOGFILE and one for
        the console.
    '''

    LOG.handlers = []
    LOG.setLevel(level)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(funcName)s::L%(lineno)d %(message)s')
    # Log to file
    file_handler = logging.FileHandler(LOGFILE, 'a')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    LOG.addHandler(file_handler)
    # Log to console
    steam_handler = logging.StreamHandler()
    steam_handler.setLevel(level)
    LOG.addHandler(steam_handler)


def ip_changed(current_ip):
    '''
        Check if current_ip is already known from IPFILE.
    '''

    if CONFIG['only_on_ip_change']:
        # Read previous IP
        if not os.path.isfile(IPFILE):
            LOG.info('First run, writing down IP in "%s".', IPFILE)
            with open(IPFILE, 'w+') as fileh:
                fileh.write(hash_string(current_ip))
            return True
        else:
            with open(IPFILE, 'r') as fileh:
                prev_ips = fileh.readlines()
            if not hash_string(current_ip) in [i_p.strip() for i_p in prev_ips]:
                LOG.info('IP has changed.')
                return True
            LOG.info('IP has not changed. Aborting.')
    else:
        LOG.info('Skipping check based on IP change.')
    return False


def need_report(current_ip):
    '''
        Return the stolen state or the computer IP.
        If one of them is True, so we need to send a report.
    '''

    return stolen() or ip_changed(current_ip)


def public_ip():
    '''
        Returns your public IP address.
        Output: The IP address in string format.
                None if not internet connection is available.
    '''

    for distant in CONFIG['server_url'].split('|'):
        LOG.info('Retrieving IP address from %s', distant.split('/')[2])
        current_ip = request_url(distant, 'get', {'myip':'1'})
        try:
            IP(current_ip)
        except ValueError as ex:
            LOG.exception(ex)
            return None
        return current_ip

    # Make sure we are connected to the internet:
    # (If the computer has no connexion to the internet, it's no use
    # accumulating snapshots.)
    if not current_ip:
        LOG.error('Computer does not seem to be connected to the' + \
                    'internet. Aborting.')
    return None


def request_url(url, method='get', params=None):
    '''
        Make a request with all options "aux petits oignons".
    '''

    ret = str('')
    ssl_cert_verif = url.split(':') == 'https'
    auth = ()

    if CONFIG['auth_server'] == url.split('/')[2]:
        auth = (CONFIG['auth_user'], CONFIG['auth_pswd'])
    try:
        if method == 'get':
            req = requests.get(url, params=params, proxies=PROXIES,
                verify=ssl_cert_verif, auth=auth, timeout=30)
        else:
            req = requests.post(url, data=params, proxies=PROXIES,
                verify=ssl_cert_verif, auth=auth, timeout=30)
        ret = req.content.strip().decode()
    except RequestException as ex:
        LOG.error(ex)
    LOG.debug('Content: %s', ret)
    return ret


def runprocess(commandline, useshell=False):
    '''
        Runs a sub-process, wait for termination and returns
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

    LOG.debug('{0} & useshell={1}'.format(commandline, useshell))
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
            # As you may think, here we should return something telling that
            # the command failed, but few tools on Windows use STDERR to
            # print useful informations, even if the commands run as expected.
            # So we need keep a track of the false error (if any) and continue.
            LOG.error('STDERR: %s', serr)
        if sys.version > '3':
            return str(''.join(map(chr, sout)) + "\n" + ''.join(map(chr, serr)))
        else:
            return unicode(sout, ENCODING).encode('utf-8') + \
                    "\n" + unicode(serr, ENCODING).encode('utf-8')
    except subprocess.CalledProcessError as ex:
        LOG.error('Process failed: %s', ex)
    return ''


def screenshot(filename):
    '''
        Takes a screenshot and returns the path to the saved image
        (in TMP). None if could not take the screenshot.
    '''

    if not CONFIG['screenshot']:
        LOG.info('Skipping screenshot.')
        return None

    temp = tempfile.gettempdir()
    LOG.info('Taking screenshot')
    filepath = '{0}_screenshot'.format(os.path.join(temp, filename))
    if not USER:
        LOG.error('Could not determine current user. Cannot take screenshot.')
        return None

    if OS == 'Windows':
        try:
            img = mss.MSSWindows()
            for filename in img.save(output=filepath, oneshot=True):
                filepath = filename
        except ValueError as ex:
            LOG.exception(ex)
    else:
        filepath += '.jpg'
        cmd = CONFIG['screenshot']
        cmd = cmd.replace('<user>', USER)
        cmd = cmd.replace('<filepath>', filepath)
        runprocess(cmd, useshell=True)
    if not os.path.isfile(filepath):
        return None
    return filepath


def snapshot_sendto_server(filename, filepath, data):
    '''
        Compute authentication token and send the report to all servers.
    '''

    filedata = base64.b64encode(data)
    filesize = file_size(filepath)
    os.remove(filepath)
    key = CONFIG['password']
    if sys.version > '3':
        key = key.encode()
        msg = str(filedata.decode()) + '***' + filename
        msg = msg.encode()
    else:
        msg = filedata + '***' + filename
    authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()

    # Send to the webserver (HTTP POST).
    parameters = {'filename':filename, 'filedata':filedata,
                'token':authtoken}
    for distant in CONFIG['server_url'].split('|'):
        LOG.info('Sending file (%s) to %s', filesize, distant.split('/')[2])
        request_url(distant, 'post', parameters)
    return


def snapshot(current_ip):
    '''
        Make a global snapshot of the system (ip, screenshot, webcam...)
        and sends it to the internet.
        If not internet connexion is available, will exit.
    '''

    # Note: when making a snapshot, we will try each and every type
    # of snapshot (screenshot, webcam, etc.)
    # If a particular snapshot fails, it will simply skip it.

    # Initialisations
    temp = tempfile.gettempdir()
    report_name = platform.node() + time.strftime('_%Y%m%d_%H%M%S')

    # Create the system report (IP, date/hour...)
    LOG.info('Filename: %s', report_name)
    LOG.info('Collecting system info')
    filepath = '{0}.txt'.format(os.path.join(temp, report_name))
    with open(filepath, 'a') as fileh:
        fileh.write(system_report(current_ip))
    filestozip = []
    filestozip.append(filepath)

    # Take a screenshot
    screen = screenshot(report_name)
    if screen:
        filestozip.append(screen)

    # Take a webcam snapshot
    webcam = webcamshot(report_name)
    if webcam:
        filestozip.append(webcam)

    # Zip files:
    LOG.info('Zipping files')
    os.chdir(temp)
    zipfilepath = '{0}.zip'.format(os.path.join(temp, report_name))
    fileh = zipfile.ZipFile(zipfilepath, 'w', zipfile.ZIP_DEFLATED)
    for filepath in filestozip:
        fileh.write(os.path.basename(filepath))
    fileh.close()

    # Remove temporary files.
    for filepath in filestozip:
        os.remove(filepath)

    # Encrypt using gpg with a specified public key
    gpgfilepath = zipfilepath
    if CONFIG['gpgkeyid'] == 'i_dont_wanna_use_encryption_and_i_assume':
        # You shall not pass!
        LOG.info('Skipping encryption (bad, Bad, BAD ...)')
        os.rename(zipfilepath, gpgfilepath)
    else:
        LOG.info('Encrypting zip with GnuPG')
        if CONFIG['gpg_binary'] == '':
            LOG.critical('The path to the GPG binary is not set. Aborting.')
            sys.exit(1)
        gpgfilepath += '.gpg'
        runprocess([CONFIG['gpg_binary'], '--batch', '--no-default-keyring',
                    '--trust-model', 'always', '-r', CONFIG['gpgkeyid'],
                    '-o', gpgfilepath, '-e', zipfilepath])
        os.remove(zipfilepath)
        if not os.path.isfile(gpgfilepath):
            LOG.critical('GPG encryption failed. Aborting.')
            sys.exit(1)

    # Read GPG file
    with open(gpgfilepath, 'r+b') as fileh:
        data = fileh.read()
    gpgfilename = os.path.basename(gpgfilepath)

    # Send to all servers
    snapshot_sendto_server(gpgfilename, gpgfilepath, data)
    return


def stolen():
    '''
        Returns True is the computer was stolen.
    '''

    salt = 'just check if I am a stolen one'
    key = CONFIG['password']
    msg = salt + '***' + CONFIG['check_file']
    if sys.version > '3':
        key = key.encode()
        msg = msg.encode()
    authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()
    parameters = {'filename':CONFIG['check_file'],
                'filedata':salt, 'verify':authtoken}
    for distant in CONFIG['server_url'].split('|'):
        LOG.info('Checking status on %s', distant.split('/')[2])
        if request_url(distant, 'post', parameters) == '1':
            LOG.info('<<!>> Stolen computer <<!>>')
            return True
    LOG.info('Computer *does not* appear to be stolen.')
    return False


def system_report(current_ip):
    '''
        Returns a system report: computer name, date/time, public IP,
        list of wired and wireless interfaces and their configuration, etc.
    '''

    separator = "\n" + 75 * "-" + "\n"
    ver = sys.version_info
    LOG.debug('Using python %s.%s.%s', ver.major, ver.minor, ver.micro)
    report  = 'Pombo {0} report'.format(__version__) + separator
    report += str('Username : ' +  USER) + "\n"
    report += str('Computer : ' +  get_manufacturer()) + "\n"
    report += str('Serial/N : ' +  get_serial()) + "\n"
    report += str('System   : ' +  ' '.join(platform.uname())) + separator
    report += 'Public IP: {0} ( Approximate geolocation: {1}{0}'.format(
                current_ip, 'http://www.geoiptool.com/?IP=')
    report += separator
    report += 'Date/time: {0} (local time)'.format(datetime.datetime.now())
    report += separator
    separator = "\n" + separator

    # Primary commands, the Network stuff ...
    todo = [
        ('network_config','Network config'),
        ('wifi_access_points','Nearby wireless access points'),
        ('traceroute','Network routes'),
        ('network_trafic','Current network connections')
    ]
    for key, info in todo:
        LOG.debug('System report: %s()', key)
        report += str("{0}:\n").format(info)
        if not CONFIG[key]:
            report += 'Disabled.'
        else:
            informations = runprocess(CONFIG[key].split(' '))
            report += str(informations.strip())
        report += separator
    report += str("Report end.\n")

    if OS == 'Windows':
        report = report.replace("\r\n", "\n")
    return report


def to_bool(value=''):
    '''
        Return a boolean of a given string.
    '''

    return str(value).lower() in {'true', 'oui', 'yes', 'on', '1'}


def webcamshot(filename):
    '''
        Takes a snapshot with the webcam and returns the path to the
        saved image (in TMP). None if could not take the snapshot.
    '''

    if not CONFIG['camshot']:
        LOG.info('Skipping webcamshot.')
        return None

    temp = tempfile.gettempdir()
    LOG.info('Taking webcamshot')
    if OS == 'Windows':
        filepath = '{0}_webcam.jpg'.format(os.path.join(temp, filename))
        try:
            cam = Device(devnum=0)
            if not cam:
                cam = Device(devnum=1)
        except Exception as ex:
            LOG.exception('vidcap.Error: %s', ex)
            return None
        try:
            # Here you can modify the picture resolution
            #cam.setResolution(768, 576)
            cam.getImage()
            time.sleep(1)
            cam.saveSnapshot(filepath)
        except ValueError as ex:
            LOG.error(ex)
            return None
    else:
        filepath = '{0}_webcam.{1}'.format(os.path.join(temp, filename),
                    CONFIG['camshot_filetype'])
        cmd = CONFIG['camshot'].replace('<filepath>', filepath)
        runprocess(cmd, useshell=True)
        if os.path.isfile(filepath):
            if CONFIG['camshot_filetype'] == 'ppm':
                new_filepath = '{0}_webcam.jpg'.format(
                                os.path.join(temp, filename))
                runprocess(['/usr/bin/convert', filepath, new_filepath])
                os.unlink(filepath)
                filepath = new_filepath
    if not os.path.isfile(filepath):
        return None
    return filepath


# ----------------------------------------------------------------------
# --- [ Pombo options ] ------------------------------------------------
# ----------------------------------------------------------------------

def pombo_add():
    '''
        Add an IP to the IPFILE if not already known.
    '''

    config()
    current_ip = public_ip()
    if not current_ip:
        return
    known = False
    if os.path.isfile(IPFILE):
        # Read previous IP
        with open(IPFILE, 'r') as fileh:
            previous_ips = fileh.readlines()
            if hash_string(current_ip) in [s.strip() for s in previous_ips]:
                print('IP already known.')
                known = True
    if not known:
        print('Adding current ip {0} to {1}'.format(current_ip, IPFILE))
        with open(IPFILE, 'a+') as fileh:
            fileh.write(hash_string(current_ip) + "\n")


def pombo_help():
    '''
        Print help message.
    '''

    print('Options ---')
    print('   add      add the current IP to {0}'.format(IPFILE))
    print('   check    launch Pombo in verbose mode')
    print('   help     show this message')
    print('   ip       show current IP')
    print('   list     list known IP')
    print('   update   check for update')
    print('   version  show Pombo, python and PIL versions')


def pombo_ip():
    '''
        Print the current IP.
    '''

    config()
    current_ip = public_ip()
    if not current_ip:
        return
    print('IP  : {0}'.format(current_ip))
    iphash = hash_string(current_ip)
    print('Hash: {0}...{1}'.format(iphash[:20], iphash[-20:]))


def pombo_list():
    '''
        Print known IPs from IPFILE.
    '''

    if not os.path.isfile(IPFILE):
        print('{0} does not exist!'.format(IPFILE))
    else:
        with open(IPFILE, 'r') as fileh:
            print('IP hashes in {0}:'.format(IPFILE))
            for ip_h in fileh.readlines():
                print('   {0}...{1}'.format(ip_h[:20], ip_h.strip()[-20:]))


def pombo_update():
    '''
        Check for a newer version.
    '''

    version = ''
    try:
        req = requests.get(UPLINK, verify=True)
    except ConnectionError as ex:
        print(' ! Arf, check failed: {0} !'.format(ex))
        print(' . Please check later.')
        return
    version = req.content.strip().decode()
    if version > __version__:
        if 'a' in version or 'b' in version:
            print(' - Developement version available: {0}'.format(version))
            print(' . You should upgrade only for tests purpose!')
            print(' - Check {0}'.format(URL))
            print('   and report issues/ideas on GitHub')
        else:
            print(' + Yep! A new version is available: {0}'.format(version))
            print(' - Check {0} for upgrade.'.format(URL))
    if version < __version__:
        print('Ouhou! It seems that you are in advance on your time ;)')
    else:
        print('Version is up to date!')


def pombo_version():
    '''
        Print Pombo and modules versions.
    '''

    ver = sys.version_info
    print('I am using python {0}.{1}.{2}'.format(
            ver.major, ver.minor, ver.micro))
    if OS == 'Windows':
        print('with VideoCapture {0}'.format(VCVERSION))
        print('            & MSS {0}'.format(mss.__version__))
        print('            & PIL {0}'.format(Image.VERSION))


def pombo_work(testing=False):
    '''
        Primary function, it will launch the report based on the
        stolen state.
    '''

    config()
    if testing:
        install_log_handlers(logging.DEBUG)
        LOG.info('[Test] Simulating stolen computer ...')
        current_ip = public_ip()
        if current_ip is None:
            LOG.error('Test cannot continue ...')
            return
        snapshot(current_ip)
        wait_stolen = CONFIG['time_limit'] // 3
        LOG.info('==> In real scenario, Pombo will send a report each' + \
                ' {0} minutes.'.format(wait_stolen))
    else:
        if OS == 'Windows':
            # Cron job like for Windows :s
            while True:
                wait_normal = 60 * CONFIG['time_limit']
                wait_stolen = wait_normal // 3
                current_ip = public_ip()
                if current_ip and need_report(current_ip):
                    start = time.time()
                    snapshot(current_ip)
                    runtime = time.time() - start
                    time.sleep(wait_stolen - runtime)
                else:
                    time.sleep(wait_normal)
        else:
            current_ip = public_ip()
            if current_ip and need_report(current_ip):
                wait = 60 * CONFIG['time_limit'] // 3
                for i in range(1, 4):
                    LOG.info('* Attempt %d/3 *', i)
                    start = time.time()
                    snapshot(current_ip)
                    runtime = time.time() - start
                    if i < 3:
                        time.sleep(wait - runtime)


# ----------------------------------------------------------------------
# --- [ C'est parti mon kiki ! ] ---------------------------------------
# ----------------------------------------------------------------------

if __name__ == '__main__':

    if not os.access(CONF, os.R_OK):
        print(' ! Impossible to read the config file.')
        sys.exit(1)

    try:
        LOG = logging.getLogger()
        USER = current_user()
        install_log_handlers()
        print('Pombo {0}'.format(__version__))
        if len(sys.argv) > 1:
            if   sys.argv[1] == 'add':
                pombo_add()
            elif sys.argv[1] == 'check':
                pombo_work(testing=True)
            elif sys.argv[1] == 'help':
                pombo_help()
            elif sys.argv[1] == 'ip':
                pombo_ip()
            elif sys.argv[1] == 'list':
                pombo_list()
            elif sys.argv[1] == 'update':
                pombo_update()
            elif sys.argv[1] == 'version':
                pombo_version()
            else:
                LOG.warning('Unknown argument "%s" - try "help".', sys.argv[1])
        else:
            LOG.debug('Log file is %s', LOGFILE)
            pombo_work()
            LOG.info('Session terminated.')
    except KeyboardInterrupt:
        LOG.warning('*** STOPPING operations ***')
        sys.exit(1)
    except Exception as ex:
        LOG.exception(ex)
        raise
