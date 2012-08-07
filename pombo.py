#!/usr/bin/python
# -*- coding: utf-8 -*-

# Pombo
# Theft-recovery tracking opensource software
# http://sebsauvage.net/pombo
# http://bobotig.fr/contenu/projets/pombo

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
PROGRAMVERSION = '0.1.0'

import base64,ConfigParser,datetime,hashlib,hmac,locale,os,platform,\
       random,re,subprocess,sys,tempfile,time,urllib,urllib2,zipfile


# ----------------------------------------------------------------------
# --- [ Variables ] ----------------------------------------------------
# ----------------------------------------------------------------------

# Current running OS specifities
OS     = 'GNULINUX'
SEP    = '/'
CONF   = '/etc/pombo.conf'
IPFILE = '/var/local/pombo'
if os.name == 'nt':
	os.chdir(sys.path[0])
	OS     = 'WINDOWS'
	SEP    = '\\'
	CONF   = 'pombo.conf'
	IPFILE = 'pombo'

# Console encoding
encoding = sys.stdin.encoding or locale.getdefaultlocale()[1]
if not encoding:
	encoding = 'utf-8'

# Output
DEBUG = False
if 'check' in sys.argv:
	DEBUG = True

# Get the configuration options
if not os.access(CONF, os.R_OK):
	print ' ! Impossible to read the config file.'
	sys.exit(1)
config = ConfigParser.SafeConfigParser()
config.read(CONF)
# Pombo related
GPGKEYID  = config.get('GENERAL','gpgkeyid').strip()
PASSWORD  = config.get('GENERAL','password').strip()
SERVERURL = config.get('GENERAL','serverurl').strip()
ONLYONIPCHANGE = config.get('GENERAL','onlyonipchange').strip()
if ONLYONIPCHANGE != 'True' and ONLYONIPCHANGE != 'False':
	print ' ! Config file error: wrong "onlyonipchange" parameter, should be True or False.'
	print '   Considering False.'
	ONLYONIPCHANGE = 'False'
CHECKFILE = config.get('GENERAL','checkfile').strip()
# Additional tools
NETWORK_CONFIG     = config.get(OS,'network_config').strip()
WIFI_ACCESS_POINTS = config.get(OS,'wifi_access_points').strip()
TRACEROUTE         = config.get(OS,'traceroute').strip()
NETWORK_TRAFIC     = config.get(OS,'network_trafic').strip()
SCREENSHOT         = config.get(OS,'screenshot').strip()
CAMSHOT            = config.get(OS,'camshot').strip()
RECOMPRESSION      = config.get(OS,'recompression').strip()
if OS == 'GNULINUX':
	CAMSHOT_FILETYPE = config.get(OS,'camshot_filetype').strip()
if SERVERURL == '':
	print ' ! Please specifiy at least one server for SERVERURL option.'
	sys.exit(1)

# Temporary directory
TMP = tempfile.gettempdir()

# Prefix used to name files (computer name + date/time)
PREFIX = platform.node() + time.strftime('_%Y%m%d_%H%M%S')


# ----------------------------------------------------------------------
# --- [ Functions ] ----------------------------------------------------
# ----------------------------------------------------------------------

def current_network_connections():
	''' Returns the addresses and ports to which this computer is 
	    currently connected to. '''
	if NETWORK_TRAFIC == 'False':
		return 'Disabled.'
	return runprocess(NETWORK_TRAFIC.split(' '))

def currentuser():
	''' Return the user who is currently logged in and uses the X 
	    session. None if could not be determined.
	'''
	user = None
	if OS == 'WINDOWS':
		user = runprocess(['echo', '%USERNAME%'], useshell = True)
	else:
		for line in runprocess(['who','-s']).split('\n'):
			if '(:0)' in line:
				user = line.split(' ')[0]
	return user

def ip_hash(ip):
	''' IP hash methods - could be easily modifed. '''
	return hashlib.sha256(ip.strip()).hexdigest()

def network_config():
	''' Returns the network configuration, both wired and wireless '''
	if NETWORK_CONFIG == 'False':
		return 'Disabled.'
	return runprocess(NETWORK_CONFIG.split(' '))

def network_route():
	''' Returns a traceroute to a public server in order to detect ISPs
	    and nearby routeurs.
	'''
	if TRACEROUTE == 'False':
		return 'Disabled.'
	return runprocess(TRACEROUTE.split(' '))

def png_recompression(filepath, what):
	''' PNG recompression. '''
	if RECOMPRESSION != 'False':
		os.system(RECOMPRESSION % filepath)
		filepathnq8 = '%s%c%s_%s-nq8.png' % (TMP, SEP, PREFIX, what)
		if not os.path.isfile(filepathnq8):
			_print(' ! Skipping image recompression: %s failed.' % RECOMPRESSION.split(' ')[0])
		else:
			os.unlink(filepath)   
			os.rename(filepathnq8, filepath)
	return

def _print(string):
	if DEBUG:
		print('%s %s' % (datetime.datetime.now(), string))
	return

def public_ip():
	''' Returns your public IP address.
		Output: The IP address in string format.
				None if not internet connection is available.
	'''
	_print(' - Checking connectivity to the internet.')
	ip_regex = re.compile('(([0-9]{1,3}\.){3}[0-9]{1,3})')
	request = urllib2.Request(SERVERURL.split(',')[0], urllib.urlencode({'myip':'1'}))
	try:
		response = urllib2.urlopen(request)
		ip = response.read(256)
		if ip_regex.match(ip):
			return ip
	except Exception as ex:
		pass
	return None

def runprocess(commandline,useshell=False):
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
		return unicode(sout, encoding).encode('utf-8') + "\n" + unicode(serr, encoding).encode('utf-8')
	except Exception as ex:  # Yeah, I know this is bad
		_print(' ! Process failed: %s (%s)' % (commandline, ex))
		return ''

def screenshot():
	''' Takes a screenshot and returns the path to the saved image 
	    (in /tmp). None if could not take the screenshot. 
	'''
	if SCREENSHOT == 'False':
		_print(' . Skipping screenshot.')
		return None

	_print(' - Taking screenshot.')
	filepath = '%s%c%s_screenshot.png' % (TMP, SEP, PREFIX)
	user = currentuser()
	#if not user:
	#	_print(' ! Could not determine current user. Cannot take screenshot.')
	#	return None

	if OS == 'WINDOWS':
		from PIL import ImageGrab
		img = ImageGrab.grab() 
		img.save(filepath, 'PNG')
	else:
		os.system(SCREENSHOT % filepath)
	if not os.path.isfile(filepath):
		return None
	png_recompression(filepath, 'screenshot')
	return filepath

def snapshot(stolen, public_ip):
	''' Make a global snapshot of the system (ip, screenshot, webcam...)
		and sends it to the internet.
		If not internet connexion is available, will exit.
	'''
	# Note: when making a snapshot, we will try each and every type
	# of snapshot (screenshot, webcam, etc.)
	# If a particular snapshot fails, it will simply skip it.

	filestozip = []  # List of files to include in the zip file (full path)

	# Make sure we are connected to the internet:
	# (If the computer has no connexion to the internet, it's no use 
	# accumulating snapshots.)
	if public_ip is None:
		_print(' - Computer does not seem to be connected to the internet. Aborting.')
		return

	if not stolen and ONLYONIPCHANGE == 'True':
		# Read previous IP
		if not os.path.isfile(IPFILE):
			# First run: file containing IP is no present.
			_print(' + First run, writing down IP in pombo.')
			f = open(IPFILE, 'w+b')
			f.write(ip_hash(public_ip))
			f.close()
		else:
			f = open(IPFILE, 'rb')
			previous_ips = f.readlines()
			f.close()
			if ip_hash(public_ip) in [s.strip() for s in previous_ips]:
				_print(' - IP has not changed. Aborting.')
				return
			_print(' + IP has changed.')

	# Create the system report (IP, date/hour...)
	_print(' - Collecting system info.')
	filepath = '%s%c%s.txt' % (TMP, SEP, PREFIX)
	f = open(filepath, 'ab')
	f.write(systemreport(public_ip))
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
	_print(' - Zipping files.')
	os.chdir(TMP)
	zipfilepath = '%s%c%s.zip' % (TMP, SEP, PREFIX)
	f = zipfile.ZipFile(zipfilepath, 'w', zipfile.ZIP_DEFLATED)
	for filepath in filestozip:
		f.write(os.path.basename(filepath))
	f.close()

	# Remove temporary files.
	for filepath in filestozip:
		os.remove(filepath)

	# Encrypt using gpg with a specified public key
	_print(' - Encrypting zip with GnuPG.')
	os.system('gpg --batch --no-default-keyring --trust-model always -r %s -e "%s"' % (GPGKEYID, zipfilepath))
	os.remove(zipfilepath)
	gpgfilepath = zipfilepath + '.gpg'
	if not os.path.isfile(gpgfilepath):
		_print(' ! GPG encryption failed. Aborting.')
		return

	# Read GPG file and compute authentication token
	f = open(gpgfilepath, 'r+b')
	filedata = base64.b64encode(f.read())
	f.close()
	os.remove(gpgfilepath)
	gpgfilename = os.path.basename(gpgfilepath)
	authtoken = hmac.new(PASSWORD, filedata + '***' + gpgfilename, hashlib.sha1).hexdigest()

	# Send to the webserver (HTTP POST).
	for distant in SERVERURL.split(','):
		domain = distant.split('/')[2]
		_print(' - Sending to %s ...' % (domain))
		parameters = {'filename':gpgfilename, 'filedata':filedata, 'token':authtoken}
		request = urllib2.Request(distant, urllib.urlencode(parameters))
		try:
			response = urllib2.urlopen(request)
			page = response.read(2000)
			_print('	 + Server responded: %s' % page.strip())
		except Exception as ex:
			_print('	 ! Failed to send to server: %s' % ex)
			if DEBUG:
				return
			else:
				pass
	_print(' ^ Done.')
	return

def stolen():
	''' Returns True is the computer was stolen. '''

	# Check the CHECKFILE for each webserver (HTTP POST).
	salt = 'just check if I am a stolen one'
	authtoken = hmac.new(PASSWORD, salt + '***' + CHECKFILE, 
						 hashlib.sha1).hexdigest()
	for distant in SERVERURL.split(','):
		domain = distant.split('/')[2]
		_print(' - Checking %s ...' % domain)
		parameters = {'filename':CHECKFILE, 'filedata':salt, 'verify':authtoken}
		request = urllib2.Request(distant, urllib.urlencode(parameters))
		try:
			response = urllib2.urlopen(request)
			page = response.read(2000)
			if page.strip() == '1':
				_print('	 + Stolen computer!')
				return True
		except Exception as ex:
			_print('	 ! Failed to check to server because: %s' % ex)
	return False

def systemreport(public_ip):
	''' Returns a system report: computer name, date/time, public IP,
		list of wired and wireless interfaces and their configuration, etc.
	'''
	report = ['%s %s report' % (PROGRAMNAME, PROGRAMVERSION)]
	report.append('Computer : ' +  ' '.join(platform.uname()))
	report.append('Public IP: %s ( Approximate geolocation: http://www.geoiptool.com/?IP=%s )' % (public_ip, public_ip))
	report.append('Date/time: %s (local time)' % datetime.datetime.now())
	report.append("Network config:\n" + network_config())
	report.append("Nearby wireless access points:\n" + wifiaccesspoints())
	report.append("Network routes:\n" + network_route())
	report.append("Current network connections:\n" + current_network_connections())
	separator = "\n" + 75 * "-" + "\n"
	return separator.join(report)

def webcamshot():
	''' Takes a snapshot with the webcam and returns the path to the 
	    saved image (in /tmp). None if could not take the snapshot. 
	'''
	if CAMSHOT == 'False':
		_print(' . Skipping webcamshot.')
		return None

	_print(' - Taking webcamshot.')
	if OS == 'WINDOWS':
		try:
			filepath = '%s%c%s_webcam.png' % (TMP, SEP, PREFIX)
			from VideoCapture import Device
			cam = Device(devnum=0)
			if not cam:
				cam = Device(devnum=1)
				if not cam:
					_print(' ! Error while taking webcamshot: no device available.')
					return None
			camshot = cam.getImage()
			time.sleep(1)
			try:
				cam.saveSnapshot(filepath)
				png_recompression(filepath, 'webcam')
			except Exception as ex:
				try:
					if os.path.isfile(filepath):
						os.unlink(filepath)
					filepath = '%s%c%s_webcam.jpg' % (TMP, SEP, PREFIX)
					cam.saveSnapshot(filepath)
				except Exception as ex:
					_print(' ! Error while taking webcamshot: %s' % ex[0])
					return None
		except Exception as ex:
			_print(' ! Error while taking webcamshot: %s' % ex[0])
			return None
	else:
		filepath = '%s%c%s_webcam.%s' % (TMP, SEP, PREFIX, CAMSHOT_FILETYPE)
		try:
			os.system(CAMSHOT % filepath)
		except Exception as ex:
			_print(' ! Error while taking webcamshot: %s' % ex[0])
			return None
		if os.path.isfile(filepath):
			if CAMSHOT_FILETYPE == 'ppm':
				new_filepath = '%s%c%s_webcam.png' % (TMP, SEP, PREFIX)
				os.system('/usr/bin/convert %s %s' % (filepath, new_filepath))
				os.unlink(filepath)
				filepath = new_filepath
				png_recompression(filepath, 'webcam')
			if CAMSHOT_FILETYPE == 'png':
				png_recompression(filepath, 'webcam')
	if not os.path.isfile(filepath):
		return None
	return filepath

def wifiaccesspoints():
	''' Returns a list of nearby wifi access points (AP). '''
	if WIFI_ACCESS_POINTS == 'False':
		return 'Disabled.'
	return runprocess(WIFI_ACCESS_POINTS.split(' '))

if __name__ == '__main__':
	_print('%s %s' % (PROGRAMNAME, PROGRAMVERSION))
	
	argv = sys.argv[1:]
	if 'add' in argv:
		publicip = public_ip()
		if not publicip:
			print 'Computer does not seem to be connected to the internet. Aborting.'
		else:
			known = False
			if os.path.isfile(IPFILE):
				# Read previous IP
				f = open(IPFILE, 'rb')
				previous_ips = f.readlines()
				f.close()
				if ip_hash(publicip) in [s.strip() for s in previous_ips]:
					print 'IP already known.'
					known = True
			if known is False:
				print 'Adding current ip %s to %s.' % (publicip, IPFILE)
				f = open(IPFILE, 'a+b')
				f.write(ip_hash(publicip) + "\n")
				f.close()
	elif 'help' in argv:
		print '%s %s' % (PROGRAMNAME, PROGRAMVERSION)
		print 'Options ---'
		print '   add : add the current IP to %s' % IPFILE
		print '   ip  : show your IP'
		print '   list: list known IP'
	elif 'ip' in argv:
		publicip = public_ip()
		if not publicip:
			print 'Computer does not seem to be connected to the internet. Aborting.'
		else:
			print 'Current IP is %s:' % publicip
			print 'Hash is %s.' % ip_hash(publicip)
	elif 'list' in argv:
		if not os.path.isfile(IPFILE):
			print '%s does not exist!' % IPFILE
		else:
			f = open(IPFILE, 'rb')
			print 'IP hashes in %s:' % IPFILE
			for s in f.readlines():
				print '   %s' % s.strip()
			f.close()
	else:
		# Cron job like for Windows :s
		if OS == 'WINDOWS':
			while True:
				if stolen():
					snapshot(True, public_ip())
					time.sleep(300) # 5 minutes
				else:
					snapshot(False, public_ip())
					time.sleep(900) # 15 minutes
		else:
			if stolen():
				for i in range(1, 2):
					snapshot(True, public_ip())
					time.sleep(300) # 5 minutes
			else:
				snapshot(False, public_ip())
