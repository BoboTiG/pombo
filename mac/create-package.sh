#!/bin/sh -e
#
# Package creation for Pombo (Mac OSX).
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
output="pombo-$version-macosx.tar.gz"
tar -cf - $files | gzip -f >$output
