#!/bin/sh -e
#
# Package creation for Pombo (GNU/Linux).
#

files=" check-imports.py \
        install.sh \
        uninstall.sh \
        ../icon/pombo.svg \
        ../CREDITS \
        ../INSTALL \
        ../LICENSE \
        ../pombo.conf \
        ../pombo.py \
        ../README.md \
        ../REQUIREMENTS \
        ../VERSION \
"

[ -z "$1" ] && version=$(cat ../VERSION) || version="$1"
output="pombo-$version.tar.gz"
tar -cf - $files | gzip -f >$output
