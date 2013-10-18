#!/bin/sh -e
#
# Calcute SHA1 sums for Pombo packages.
#

file=control.sha1
[ -f $file ] && rm $file
touch $file
for package in $(ls pombo-* | sed 's/*//' | sort -V); do
    sha1sum $package >>$file;
done
