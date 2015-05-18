#!/bin/sh -e
#
# Calcute SHA1 sums for Pombo packages.
#

file=control.sha1
[ -f $file ] && rm $file
sha1sum pombo-* >$file
