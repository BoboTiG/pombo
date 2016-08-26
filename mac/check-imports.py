#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Pombo - check for needed modules

ok = False
for m in ['mss', 'requests', 'IPy']:
    try:
        __import__(m)
    except Exception as ex:
        print(' ! Python module needed but not installed: %s' % m)
        ok = True
exit(ok)
