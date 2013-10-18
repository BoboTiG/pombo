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


__version__ = '0.0.11-a4'
__author__  = 'BoboTiG'
__date__    = '$18-Oct-2013 12:57:57$'


import base64
import datetime
import hashlib
import hmac
import locale
import logging
import os
import platform
import re
import smtplib
import subprocess
import sys
import tempfile
import time
import zipfile


from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

try:
    import requests
    from requests.exceptions import ConnectionError, RequestException
    from IPy import IP
    if os.name == 'nt':
        from PIL import Image, ImageGrab
        from VideoCapture import Device
        from mss import MSSWindows
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
oses = {'Linux': 'Linux', 'Darwin': 'Mac', 'Windows': 'Windows'}
try:
    OS = oses[platform.system()]
except keyError:
    print('System not implemented.')
    sys.exit(1)
SEP     = '/'
CONF    = '/etc/pombo.conf'
IPFILE  = '/var/local/pombo'
LOGFILE = '/var/log/pombo.log'
if os.name == 'nt':
    SEP     = '\\'
    IPFILE  = 'c:\\pombo\\pombo'
    CONF    = 'c:\\pombo\\pombo.conf'
    LOGFILE = tempfile.gettempdir() + SEP + 'pombo.log'
    VCVERSION = '0.9.5'

# Console encoding
ENCODING = sys.stdin.encoding or locale.getdefaultlocale()[1]
if not ENCODING:
    ENCODING = 'utf-8'

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
    try:
        conf = ConfigParser.SafeConfigParser()
        conf.read(CONF)
    except ConfigParser.Error as ex:
        LOG.error(ex)

    # Primary parameters
    CONFIG['gpgkeyid'] = conf.get('General', 'gpgkeyid') or None
    CONFIG['password'] = conf.get('General', 'password') or None
    CONFIG['server_url'] = conf.get('General', 'server_url') or None
    CONFIG['check_file'] = conf.get('General', 'check_file') or None
    CONFIG['time_limit'] = conf.getint('General', 'time_limit') or 15
    error = False
    for key in CONFIG:
        if CONFIG[key] is None:
            LOG.error('Config error: empty %s parameter.', key)
            error = True
    if error:
        LOG.warn('Pombo has to stop, please check parameters.')
        sys.exit(0)

    # Secondary parameters (auth., email, commands, ...)
    CONFIG['email_id'] = conf.get('General', 'email_id') or ''
    CONFIG['only_on_ip_change'] = conf.getboolean('General',
                                            'only_on_ip_change') or False
    CONFIG['enable_log'] = conf.getboolean('General', 'enable_log') or False
    CONFIG['use_proxy'] = conf.getboolean('General', 'use_proxy') or False
    CONFIG['use_env'] = conf.getboolean('General', 'use_env') or False
    CONFIG['http_proxy'] = conf.get('General', 'http_proxy') or ''
    CONFIG['https_proxy'] = conf.get('General', 'https_proxy') or ''
    CONFIG['auth_server'] = conf.get('General', 'auth_server') or ''
    CONFIG['auth_user'] = conf.get('General', 'auth_user') or ''
    CONFIG['auth_pswd'] = conf.get('General', 'auth_pswd') or ''
    CONFIG['network_config'] = conf.get('Commands', 'network_config') or ''
    CONFIG['wifi_access_points'] = conf.get('Commands',
                                            'wifi_access_points') or ''
    CONFIG['traceroute'] = conf.get('Commands', 'traceroute') or ''
    CONFIG['network_trafic'] = conf.get('Commands', 'network_trafic') or ''
    CONFIG['network_trafic'] = conf.get('Commands', 'network_trafic') or ''
    CONFIG['screenshot'] = conf.get('Commands', 'screenshot') or ''
    CONFIG['camshot'] = conf.get('Commands', 'camshot') or ''
    CONFIG['camshot_filetype'] = conf.get('Commands', 'camshot_filetype') or ''

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
        LOG.info('Disabling logger')
        LOG.handlers = []


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
    return user


def get_manufacturer():
    '''
        Get the manufacturer.
    '''

    if OS == 'Windows':
        cmd = 'wmic csproduct get vendor, name, version /value'
        res = runprocess(cmd, useshell=True).strip().split("\r\n")
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
    return manufacturer


def get_serial():
    '''
        Get the serial number.
    '''

    serial = 'Unknown'
    cmd = {
        'Linux': '/usr/sbin/dmidecode --string system-serial-number',
        'Mac': '/usr/sbin/system_profiler SPHardwareDataType | grep system | cut -d: -f2',
        'Windows': 'wmic bios get serialnumber /value'
    }
    res = runprocess(cmd[OS], useshell=True).strip()
    if OS == 'Windows':
        if not res.split('=')[1] == '0':
            serial = res.split('=')[1]
    else:
        if not res == 'System Serial Number':
            serial = res
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


def install_log_handlers(level):
    '''
        Install LOG handlers: one for the file LOGFILE and one for
        the console.
    '''
    LOG.setLevel(level)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    # Log to file
    file_handler = logging.FileHandler(LOGFILE, 'a')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    LOG.addHandler(file_handler)
    # Log to console
    steam_handler = logging.StreamHandler()
    steam_handler.setLevel(logging.DEBUG)
    LOG.addHandler(steam_handler)


def ip_changed(current_ip):
    '''
        Check if current_ip is already known from IPFILE.
    '''

    if CONFIG['only_on_ip_change']:
        # Read previous IP
        if not os.path.isfile(IPFILE):
            LOG.info('First run, writing down IP in "%s".', IPFILE)
            fileh = open(IPFILE, 'w+b')
            if sys.version > '3':
                fileh.write(bytes(hash_string(current_ip), ENCODING))
            else:
                fileh.write(hash_string(current_ip))
            fileh.close()
        else:
            fileh = open(IPFILE, 'rb')
            prev_ips = fileh.readlines()
            fileh.close()
            if hash_string(current_ip) in [i_p.strip() for i_p in prev_ips]:
                LOG.info('IP has not changed. Aborting.')
                return False
            LOG.warn('IP has changed.')
            return True
    else:
        LOG.info('Skipping check based on IP change.')
    return True


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
            LOG.warning(ex)
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
        LOG.warn(ex)
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
            LOG.error(serr)
        if sys.version > '3':
            return str(''.join(map(chr, sout)) + "\n" + ''.join(map(chr, serr)))
        else:
            return unicode(sout, ENCODING).encode('utf-8') + \
                    "\n" + unicode(serr, ENCODING).encode('utf-8')
    except subprocess.CalledProcessError as ex:
        LOG.error('Process failed: %s (%s)', commandline, ex)
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
    filepath = '{0}{1}{2}_screenshot'.format(temp, SEP, filename)
    user = current_user()
    if not user:
        LOG.error('Could not determine current user. Cannot take screenshot.')
        return None

    if OS == 'Windows':
        try:
            img = MSSWindows()
            for filename in img.save(output=filepath, oneshot=True):
                filepath = filename
        except IOError as ex:
            LOG.error(ex)
    else:
        filepath += '.jpg'
        cmd = CONFIG['screenshot']
        cmd = cmd.replace('<user>', user)
        cmd = cmd.replace('<filepath>', filepath)
        runprocess(cmd, useshell=True)
    if not os.path.isfile(filepath):
        return None
    return filepath


def snapshot_email(report_name, filename, data):
    '''
        Send the report to the email account.
    '''

    if not CONFIG['email_id']:
        LOG.info('Skipping email attachment.')
        return
    superman = CONFIG['email_id']
    LOG.info('Attaching report for %s', superman)
    msg = MIMEMultipart()
    msg['Subject'] = '[Pombo report] {0}'.format(report_name)
    msg['From']    = superman
    msg['To']      = superman
    part = MIMEBase('application', 'octet-stream')
    part.add_header('Content-Disposition', 'attachment; filename="{0}"'
                    .format(filename))
    part.set_payload(data)
    encoders.encode_base64(part)
    msg.attach(part)
    try:
        conn = smtplib.SMTP('localhost')
        conn.sendmail(superman, superman, msg.as_string())
        conn.quit()
    except Exception as ex:
        LOG.error(ex)


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
    filepath = '{0}{1}{2}.txt'.format(temp, SEP, report_name)
    fileh = open(filepath, 'ab')
    if sys.version > '3':
        fileh.write(bytes(system_report(current_ip), ENCODING))
    else:
        fileh.write(system_report(current_ip))
    fileh.close()
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
    zipfilepath = '{0}{1}{2}.zip'.format(temp, SEP, report_name)
    fileh = zipfile.ZipFile(zipfilepath, 'w', zipfile.ZIP_DEFLATED)
    for filepath in filestozip:
        fileh.write(os.path.basename(filepath))
    fileh.close()

    # Remove temporary files.
    for filepath in filestozip:
        os.remove(filepath)

    # Encrypt using gpg with a specified public key
    LOG.info('Encrypting zip with GnuPG')
    runprocess(['gpg', '--batch', '--no-default-keyring',
                '--trust-model', 'always', '-r',
                CONFIG['gpgkeyid'], '-e', zipfilepath])
    os.remove(zipfilepath)
    gpgfilepath = zipfilepath + '.gpg'
    if not os.path.isfile(gpgfilepath):
        LOG.error('GPG encryption failed. Aborting.')
        return

    # Read GPG file
    fileh = open(gpgfilepath, 'r+b')
    data = fileh.read()
    fileh.close()
    gpgfilename = os.path.basename(gpgfilepath)

    # Send to all servers
    snapshot_sendto_server(gpgfilename, gpgfilepath, data)

    # Send to the email account
    snapshot_email(report_name, gpgfilename, data)
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
            LOG.warn('<<!>> Stolen computer <<!>>')
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
        filepath = '{0}{1}{2}_webcam.jpg'.format(temp, SEP, filename)
        try:
            cam = Device(devnum=0)
            if not cam:
                cam = Device(devnum=1)
        except Exception as ex:
            LOG.error('vidcap.Error: %s', ex)
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
        filepath = '{0}{1}{2}_webcam.{3}'.format(temp, SEP, filename,
                    CONFIG['camshot_filetype'])
        cmd = CONFIG['camshot'].replace('<filepath>', filepath)
        runprocess(cmd, useshell=True)
        if os.path.isfile(filepath):
            if CONFIG['camshot_filetype'] == 'ppm':
                new_filepath = '{0}{1}{2}_webcam.jpg'.format(
                                temp, SEP, filename)
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
        fileh = open(IPFILE, 'rb')
        previous_ips = fileh.readlines()
        fileh.close()
        if hash_string(current_ip) in [s.strip() for s in previous_ips]:
            print('IP already known.')
            known = True
    if known is False:
        print('Adding current ip {0} to {1}.'.format(current_ip, IPFILE))
        fileh = open(IPFILE, 'a+b')
        if sys.version > '3':
            fileh.write(bytes(hash_string(current_ip) + "\n", ENCODING))
        else:
            fileh.write(hash_string(current_ip) + "\n")
        fileh.close()


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
        fileh = open(IPFILE, 'rb')
        print('IP hashes in {0}:'.format(IPFILE))
        for ip_h in fileh.readlines():
            print('   {0}...{1}'.format(ip_h[:20], ip_h.strip()[-20:]))
        fileh.close()


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
    if version != __version__:
        if re.match('^\d{1,}.\d{1}.\d{1,}$', version):
            print(' + Yep! A new version is available: {0}'.format(version))
            print(' - Check {0} for upgrade.'.format(URL))
        elif re.match('^\d{1,}.\d{1}.\d{1,}-', version):
            typever = 'Alpha'
            if 'b' in version:
                typever = 'Beta'
            print(' - {0} version available: {1}'.format(typever, version))
            print(' . You should upgrade only for tests purpose!')
            print(' - Check {0}'.format(URL))
            print('   and report issues/ideas on GitHub or at ' + \
                    'bobotig (at) gmail (dot) com.')
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
        print('          and PIL {0}'.format(Image.VERSION))


def pombo_work(testing=False):
    '''
        Primary function, it will launch the report based on the
        stolen state.
    '''

    config()
    if testing:
        if not CONFIG['enable_log']:
            # Re-install log handlers for testing
            install_log_handlers(logging.DEBUG)
        else:
            LOG.setLevel(logging.DEBUG)

        LOG.info('[Test] Simulating stolen computer ...')
        current_ip = public_ip()
        if current_ip is None:
            LOG.error('Test cannot continue ...')
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
                if not current_ip is None and need_report(current_ip):
                    start = time.time()
                    snapshot(current_ip)
                    runtime = time.time() - start
                    time.sleep(wait_stolen - runtime)
                else:
                    time.sleep(wait_normal)
        else:
            current_ip = public_ip()
            if not current_ip is None and need_report(current_ip):
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
        install_log_handlers(logging.WARN)
        print('Pombo {0}'.format(__version__))
        if sys.argv[1:]:
            for arg in sys.argv[1:]:
                if arg == 'add':
                    pombo_add()
                elif arg == 'check':
                    pombo_work(testing=True)
                elif arg == 'help':
                    pombo_help()
                elif arg == 'ip':
                    pombo_ip()
                elif arg == 'list':
                    pombo_list()
                elif arg == 'update':
                    pombo_update()
                elif arg == 'version':
                    pombo_version()
                else:
                    LOG.warn('Unknown argument "%s" - try "help".', arg)
        else:
            LOG.debug('Log file is %s', LOGFILE)
            pombo_work()
            LOG.info('Session terminated.')
    except KeyboardInterrupt:
        LOG.warn('*** STOPPING operations ***')
        sys.exit(1)
    except Exception as ex:
        LOG.critical(ex)
        raise
