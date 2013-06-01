#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Pombo - check for needed modules
import sys

ok = False
for m in ['requests']:
	try:
		__import__(m)
	except Exception as ex:
		print(' ! python module needed but not installed: %s' % m)
		ok = True
try:
	from IPy import IP
except Exception as ex:
	print(' ! python module needed but not installed: ipy')
	ok = True

sys.exit(ok)
