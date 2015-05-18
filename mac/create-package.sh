#!/bin/sh -e
#
# Package creation for Pombo (Mac OSX).
#

[ -z "$1" ] && custom="" || custom="-$1"
files=" check-imports.py \
        install.sh \
        uninstall.sh \
        ../icon/pombo.svg \
        ../doc/* \
        ../pombo$custom.conf \
        ../pombo.php \
        ../pombo.py \
        ../README.md \
        ../VERSION \
"
version=$(cat ../VERSION)
output="pombo-$version$custom-macosx.tar.gz"
tar -cf - $files --transform "s/pombo$custom.conf/pombo.conf/" | gzip -f >$output
