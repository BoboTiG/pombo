#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Pombo
# Theft-recovery tracking opensource software
# http://bobotig.fr/?c=projets/pombo
# http://sebsauvage.net/pombo

# This program is distributed under the OSI-certified zlib/libpnglicense .
# http://www.opensource.org/licenses/zlib-license.php
# 
# This software is provided 'as-is', without any express or implied warranty.
# In no event will the authors be held liable for any damages arising from
# the use of this software.
# 
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it freely,
# subject to the following restrictions:
# 
#	 1. The origin of this software must not be misrepresented; you must not
#		claim that you wrote the original software. If you use this software
#		in a product, an acknowledgment in the product documentation would be
#		appreciated but is not required.
# 
#	 2. Altered source versions must be plainly marked as such, and must not
#		be misrepresented as being the original software.
# 
#	 3. This notice may not be removed or altered from any source distribution.

PROGRAMNAME = 'Pombo'
PROGRAMVERSION = '0.0.11-a0'
URL = 'https://github.com/BoboTiG/pombo'
UPLINK = 'https://raw.github.com/BoboTiG/pombo/master/VERSION'
VCVERSION = '0.9.5'

import base64,datetime,hashlib,hmac,locale,logging,os,platform,\
       re,requests,subprocess,sys,tempfile,time,zipfile
if sys.version > '3':
	import configparser as ConfigParser
else:
	import ConfigParser
from IPy import IP


# ----------------------------------------------------------------------
# --- [ Variables ] ----------------------------------------------------
# ----------------------------------------------------------------------

# Current running OS specifities
OS      = 'Gnulinux'
SEP     = '/'
CONF    = '/etc/pombo.conf'
LOGFILE = '/var/log/pombo.log'
if os.name == 'nt':
	os.chdir(sys.path[0])
	OS      = 'Windows'
	SEP     = '\\'
	CONF    = 'pombo.conf'
	LOGFILE = tempfile.gettempdir() + '\pombo.log'

# Console encoding
encoding = sys.stdin.encoding or locale.getdefaultlocale()[1]
if not encoding:
	encoding = 'utf-8'

# Informations logging
LOG = logging.getLogger()
LOG.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
# Log to file
file_handler = logging.FileHandler(LOGFILE, 'a')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
LOG.addHandler(file_handler)
# Log to console
steam_handler = logging.StreamHandler()
steam_handler.setLevel(logging.DEBUG)
LOG.addHandler(steam_handler)

# Get the configuration options
if not os.access(CONF, os.R_OK):
	print(' ! Impossible to read the config file.')
	sys.exit(1)
CONFIG = {}

# Proxies
dProxies = {}

# Others
TMP = tempfile.gettempdir()
PUBLIC_IP = None
FILENAME  = None


# ----------------------------------------------------------------------
# --- [ Functions ] ----------------------------------------------------
# ----------------------------------------------------------------------

def to_bool(value = ''):
	''' Return a boolean of a given string '''
	return str(value).lower() in {'true','oui','yes','1'}

def config():
	''' Get configuration from CONF file '''
	global CONFIG, LOG
	LOG.info('Loading configuration')
	try:
		config = ConfigParser.SafeConfigParser()
		config.read(CONF)
		CONFIG = config._sections
		CONFIG['General']['use_proxy'] = to_bool(CONFIG['General']['use_proxy'])
		CONFIG['General']['use_env'] = to_bool(CONFIG['General']['use_env'])
		CONFIG['General']['enable_log'] = to_bool(CONFIG['General']['enable_log'])
		CONFIG['General']['time_limit'] = int(CONFIG['General']['time_limit'])
	except Exception as ex:
		LOG.error(ex)
	
	if not CONFIG['General']['serverurl']:
		LOG.error('Please specifiy at least one server for "serverurl" parameter.')
		sys.exit(1)
	
	# Proxy
	if CONFIG['General']['use_proxy']:
		if CONFIG['General']['use_env']:
			if os.getenv('http_proxy') != None:
				dProxies['http'] = os.getenv('http_proxy')
			if os.getenv('https_proxy') != None:
				dProxies['https'] = os.getenv('https_proxy')
		else:
			if CONFIG['General']['http_proxy'] != '':
				dProxies['http'] = CONFIG['http_proxy']
			if CONFIG['General']['https_proxy'] != '':
				dProxies['https'] = CONFIG['https_proxy']
	
	# Informations logging
	if not CONFIG['General']['enable_log']:
		LOG.info('Disabling logger')
		LOG.handlers = []

def current_network_connections():
	''' Returns the addresses and ports to which this computer is 
	    currently connected to. '''
	if not CONFIG['Commands']['network_trafic']:
		return 'Disabled.'
	return runprocess(CONFIG['Commands']['network_trafic'].split(' '))

def currentuser():
	''' Return the user who is currently logged in and uses the X 
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

def file_size(filename):
	''' Get file to send size '''
	num = os.path.getsize(filename)
	for x in ['B','KB','MB','GB']:
		if num < 1024.0 and num > -1024.0:
			return '%3.1f%s' % (num, x)
		num /= 1024.0
	return '%3.1f%s' % (num, 'TB')

def hash_string(ip):
	''' IP hash methods - could be easily modifed. '''
	return hashlib.sha256(ip.encode()).hexdigest()

def network_config():
	''' Returns the network configuration, both wired and wireless '''
	if not CONFIG['Commands']['network_config']:
		return 'Disabled.'
	return runprocess(CONFIG['Commands']['network_config'].split(' '))

def network_route():
	''' Returns a traceroute to a public server in order to detect ISPs
	    and nearby routeurs.
	'''
	if not CONFIG['Commands']['traceroute']:
		return 'Disabled.'
	return runprocess(CONFIG['Commands']['traceroute'].split(' '))

def public_ip():
	''' Returns your public IP address.
		Output: The IP address in string format.
				None if not internet connection is available.
	'''
	for distant in CONFIG['General']['serverurl'].split('|'):
		try:
			LOG.info('Retrieving IP address from %s', distant.split('/')[2])
			ip = request_url(distant, 'get', {'myip':'1'})
			IP(ip)
			return ip
		except Exception as ex:
			LOG.warn(ex)
	return None

def request_url(url, method = 'get', params = {}):
	''' Make a request with all options "aux petits oignons" '''
	ret = str('')
	ssl_cert_verif = url.split(':') == 'https'
	auth = ()
	
	if CONFIG['General']['auth_server'] == url.split('/')[2]:
		auth = (CONFIG['General']['auth_user'], CONFIG['General']['auth_pswd'])
	try:
		if method == 'get':
			req = requests.get(url, params=params, proxies=dProxies, verify=ssl_cert_verif, auth=auth)
		else:
			req = requests.post(url, data=params, proxies=dProxies, verify=ssl_cert_verif, auth=auth)
		ret = req.content.strip().decode()
	except Exception as ex:
		LOG.warn(ex)
	LOG.debug('Content: %s', ret)
	return ret

def runprocess(commandline, useshell = False):
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
	try:
		myprocess = subprocess.Popen(commandline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=useshell)
		(sout,serr) = myprocess.communicate()
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
			return unicode(sout, encoding).encode('utf-8') + "\n" + unicode(serr, encoding).encode('utf-8')
	except Exception as ex:
		LOG.error('Process failed: %s (%s)', commandline, ex)
		return ''

def screenshot():
	''' Takes a screenshot and returns the path to the saved image 
	    (in TMP). None if could not take the screenshot. 
	'''
	if not CONFIG['Commands']['screenshot']:
		LOG.info('Skipping screenshot.')
		return None

	LOG.info('Taking screenshot')
	filepath = '%s%c%s_screenshot.jpg' % (TMP, SEP, FILENAME)
	user = currentuser()
	if not user:
		LOG.error('Could not determine current user. Cannot take screenshot.')
		return None

	try:
		if OS == 'Windows':
			from PIL import Image,ImageGrab
			img = ImageGrab.grab(Image.WEB) 
			img.save(filepath, 'JPEG', quality=80)
		else:
			cmd = CONFIG['Commands']['screenshot']
			cmd = cmd.replace('<user>', user)
			cmd = cmd.replace('<filepath>', filepath)
			runprocess(cmd, useshell=True)
	except Exception as ex:
		LOG.error(ex)
	if not os.path.isfile(filepath):
		return None
	return filepath

def snapshot(stolen):
	''' Make a global snapshot of the system (ip, screenshot, webcam...)
		and sends it to the internet.
		If not internet connexion is available, will exit.
	'''
	# Note: when making a snapshot, we will try each and every type
	# of snapshot (screenshot, webcam, etc.)
	# If a particular snapshot fails, it will simply skip it.

	# Initialisations
	global PUBLIC_IP, FILENAME
	FILENAME = platform.node() + time.strftime('_%Y%m%d_%H%M%S')
	PUBLIC_IP = public_ip()
	filestozip = []

	# Make sure we are connected to the internet:
	# (If the computer has no connexion to the internet, it's no use 
	# accumulating snapshots.)
	if PUBLIC_IP is None:
		LOG.error('Computer does not seem to be connected to the internet. Aborting.')
		return

	if not stolen:
		LOG.info('Computer not stolen, skipping report.')
		return

	# Create the system report (IP, date/hour...)
	LOG.info('Filename: %s', FILENAME)
	LOG.info('Collecting system info')
	filepath = '%s%c%s.txt' % (TMP, SEP, FILENAME)
	f = open(filepath, 'ab')
	if sys.version > '3':
		f.write(bytes(systemreport(), encoding))
	else:
		f.write(systemreport())
	f.close()
	filestozip.append(filepath)

	# Take a screenshot
	screen = screenshot()
	if screen:
		filestozip.append(screen)

	# Take a webcam snapshot
	webcam = webcamshot()
	if webcam:
		filestozip.append(webcam)

	# Zip files:
	LOG.info('Zipping files')
	try:
		os.chdir(TMP)
		zipfilepath = '%s%c%s.zip' % (TMP, SEP, FILENAME)
		f = zipfile.ZipFile(zipfilepath, 'w', zipfile.ZIP_DEFLATED)
		for filepath in filestozip:
			f.write(os.path.basename(filepath))
		f.close()
	except Exception as ex:
		LOG.error(ex)

	# Remove temporary files.
	for filepath in filestozip:
		os.remove(filepath)

	# Encrypt using gpg with a specified public key
	LOG.info('Encrypting zip with GnuPG')
	try:
		runprocess(['gpg', '--batch', '--no-default-keyring', '--trust-model', 'always', '-r', CONFIG['General']['gpgkeyid'], '-e', zipfilepath])
		os.remove(zipfilepath)
		gpgfilepath = zipfilepath + '.gpg'
		if not os.path.isfile(gpgfilepath):
			LOG.error('GPG encryption failed. Aborting.')
			return
	except Exception as ex:
		LOG.error(ex)
		return

	# Read GPG file and compute authentication token
	f = open(gpgfilepath, 'r+b')
	filedata = base64.b64encode(f.read())
	f.close()
	filesize = file_size(gpgfilepath)
	os.remove(gpgfilepath)
	gpgfilename = os.path.basename(gpgfilepath)
	key = CONFIG['General']['password']
	if sys.version > '3':
		key = key.encode()
		msg = str(filedata.decode()) + '***' + gpgfilename
		msg = msg.encode()
	else:
		msg = filedata + '***' + gpgfilename
	authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()

	# Send to the webserver (HTTP POST).
	parameters = {'filename':gpgfilename, 'filedata':filedata, 'token':authtoken}
	for distant in CONFIG['General']['serverurl'].split('|'):
		LOG.info('Sending file (%s) to %s', filesize, distant.split('/')[2])
		try:
			request_url(distant, 'post', parameters)
		except Exception as ex:
			LOG.warn(ex)
			pass
	return

def stolen():
	''' Returns True is the computer was stolen. '''
	salt = 'just check if I am a stolen one'
	key = CONFIG['General']['password']
	msg = salt + '***' + CONFIG['General']['checkfile']
	if sys.version > '3':
		key = key.encode()
		msg = msg.encode()
	authtoken = hmac.new(key, msg, hashlib.sha1).hexdigest()
	parameters = {'filename':CONFIG['General']['checkfile'], 'filedata':salt, 'verify':authtoken}
	for distant in CONFIG['General']['serverurl'].split('|'):
		LOG.info('Checking status on %s', distant.split('/')[2])
		try:
			if request_url(distant, 'post', parameters) == '1':
				LOG.warn('<<!>> Stolen computer <<!>>')
				return True
		except Exception as ex:
			LOG.warn(ex)
	return False

def systemreport():
	''' Returns a system report: computer name, date/time, public IP,
		list of wired and wireless interfaces and their configuration, etc.
	'''
	separator = "\n" + 75 * "-" + "\n"
	v = sys.version_info;
	LOG.debug('Using python %s.%s.%s' % (v.major, v.minor, v.micro))
	report  = '%s %s report' % (PROGRAMNAME, PROGRAMVERSION) + separator
	report += str('Computer : ' +  ' '.join(platform.uname())) + separator
	report += str('Public IP: %s ( Approximate geolocation: http://www.geoiptool.com/?IP=%s )' % (PUBLIC_IP, PUBLIC_IP)) + separator
	report += str('Date/time: %s (local time)' % datetime.datetime.now()) + separator
	separator = "\n" + separator
	LOG.debug('System report: network_config()')
	report += str("Network config:\n" + network_config().strip()) + separator
	LOG.debug('System report: wifiaccesspoints()')
	report += str("Nearby wireless access points:\n" + wifiaccesspoints().strip()) + separator
	LOG.debug('System report: network_route()')
	report += str("Network routes:\n" + network_route().strip()) + separator
	LOG.debug('System report: current_network_connections()')
	report += str("Current network connections:\n" + current_network_connections().strip() + "\n")
	if OS == 'Windows':
		report = report.replace("\r\n", "\n")
	return report

def webcamshot():
	''' Takes a snapshot with the webcam and returns the path to the 
	    saved image (in TMP). None if could not take the snapshot. 
	'''
	if not CONFIG['Commands']['camshot']:
		LOG.info('Skipping webcamshot.')
		return None

	LOG.info('Taking webcamshot')
	try:
		if OS == 'Windows':
			filepath = '%s%c%s_webcam.jpg' % (TMP, SEP, FILENAME)
			from VideoCapture import Device
			cam = Device(devnum=0)
			if not cam:
				cam = Device(devnum=1)
				if not cam:
					LOG.error('Error while taking webcamshot: no device available.')
					return None
			#cam.setResolution(768, 576) # Here you can modify the picture resolution
			cam.getImage()
			time.sleep(1)
			cam.saveSnapshot(filepath)
		else:
			filepath = '%s%c%s_webcam.%s' % (TMP, SEP, FILENAME, CONFIG['Commands']['camshot_filetype'])
			cmd = CONFIG['Commands']['camshot'].replace('<filepath>', filepath)
			runprocess(cmd, useshell=True)
			if os.path.isfile(filepath):
				if CONFIG['Commands']['camshot_filetype'] == 'ppm':
					new_filepath = '%s%c%s_webcam.jpg' % (TMP, SEP, FILENAME)
					runprocess(['/usr/bin/convert', filepath, new_filepath])
					os.unlink(filepath)
					filepath = new_filepath
	except Exception as ex:
		LOG.error(ex)
		return None
	if not os.path.isfile(filepath):
		return None
	return filepath

def wifiaccesspoints():
	''' Returns a list of nearby wifi access points (AP). '''
	if not CONFIG['Commands']['wifi_access_points']:
		return 'Disabled.'
	return runprocess(CONFIG['Commands']['wifi_access_points'].split(' '))


# ----------------------------------------------------------------------
# --- [ Pombo options ] ------------------------------------------------
# ----------------------------------------------------------------------

def pombo_help():
	print('Options ---')
	print('   check    launch Pombo in verbose mode')
	print('   help     show this message')
	print('   ip       show current IP')
	print('   update   check for update')
	print('   version  show %s, python and versions' % PROGRAMNAME)

def pombo_ip():
	config()
	ip = public_ip()
	if not ip:
		print('Computer does not seem to be connected to the internet. Aborting.')
	else:
		print('IP  : %s' % ip)

def pombo_update():
	version = ''
	try:
		req = requests.get(UPLINK, verify=True)
		version = req.content.strip().decode()
	except Exception as ex:
		print(' ! Arf, check failed: %s !' % ex)
		print(' . Please check later.')
	if version != PROGRAMVERSION:
		if re.match('^\d{1,}.\d{1}.\d{1,}$', version):
			print(' + Yep! A new version is available: %s' % version)
			print(' - Check %s for upgrade.' % URL)
		elif re.match('^\d{1,}.\d{1}.\d{1,}-', version):
			typever = 'Alpha'
			if 'b' in version:
				typever = 'Beta'
			print(' - %s version available: %s' % (typever, version))
			print(' . You should upgrade only for tests purpose!')
			print(' - Check %s' % URL)
			print('   and report issues/ideas on GitHub or at bobotig (at) gmail (dot) com.')
	else:
		print('Version is up to date!')

def pombo_version():
	v = sys.version_info;
	print('I am using python %s.%s.%s' % (v.major, v.minor, v.micro))
	if OS == 'Windows':
		from PIL import Image
		print('with VideoCapture %s' % VCVERSION)
		print('          and PIL %s' % Image.VERSION)

def pombo_work():
	config()
	if OS == 'Windows':
		# Cron job like for Windows :s
		while True:
			wait_normal = 60 * CONFIG['General']['time_limit']
			wait_stolen = wait_normal // 3
			if stolen():
				start = time.time()
				snapshot(True)
				runtime = time.time() - start
				time.sleep(wait_stolen - runtime)
			else:
				start = time.time()
				snapshot(False)
				runtime = time.time() - start
				time.sleep(wait_normal - runtime)
	else:
		if stolen():
			wait = 60 * CONFIG['General']['time_limit'] // 3
			for i in range(1, 4):
				LOG.info('* Attempt %d/3 *', i)
				start = time.time()
				snapshot(True)
				runtime = time.time() - start
				if i < 3:
					time.sleep(wait - runtime)
		else:
			snapshot(False)


# ----------------------------------------------------------------------
# --- [ C'est parti mon kiki ! ] ---------------------------------------
# ----------------------------------------------------------------------

try:
	if __name__ == '__main__':
		LOG.info('%s %s', PROGRAMNAME, PROGRAMVERSION)
		argv = sys.argv[1:]
		if argv:
			if 'check' in argv:
				pombo_work()
			elif 'help' in argv:
				pombo_help()
			elif 'ip' in argv:
				pombo_ip()
			elif 'update' in argv:
				pombo_update()
			elif 'version' in argv:
				pombo_version()
			else:
				LOG.warn('Unknown argument "%s" - try "help".', argv)
		else:
			pombo_work()
			LOG.info('Session terminated.')
except (KeyboardInterrupt):
	LOG.warn('*** STOPPING operations ***')
	sys.exit(1)
except Exception as ex:
	LOG.critical(ex)
	raise
