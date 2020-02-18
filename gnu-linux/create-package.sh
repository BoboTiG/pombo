#!/bin/sh -e
#
# Package creation for Pombo (GNU/Linux).
#

[ -z "$1" ] && custom="" || custom="-$1"
files=" install.sh \
        uninstall.sh \
        ../tools/check-imports.py \
        ../icon/pombo.svg \
        ../doc/* \
        ../pombo$custom.conf \
        ../pombo.php \
        ../pombo.py \
        ../README.md \
        ../VERSION \
"
version=$(cat ../VERSION)
output="pombo-$version$custom.tar.gz"
tar -cf - $files --transform "s/pombo$custom.conf/pombo.conf/" | gzip -f >$output
