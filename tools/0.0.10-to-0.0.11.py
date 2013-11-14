#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Pombo: convert the configuration file from version 0.0.10 to 0.0.11.


from os import name
from sys import exit


CONF = '/etc/pombo.conf'
if name == 'nt':
    CONF = 'c:\\pombo\\pombo.conf'

data = None
with open(CONF, 'rb') as fh:
    data = fh.read()

if not data:
    print('! Impossible to read the configuration file.')
    exit(1)

data = data.replace('serverurl', 'server_url');
data = data.replace('checkfile', 'check_file');
data = data.replace('onlyonipchange', 'only_on_ip_change');

with open(CONF, 'wb') as fh:
    fh.write(data)
    exit(0)
