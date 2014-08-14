#!/bin/sh -e
#
# Package creation for Pombo (Mac OSX).
#

files=" check-imports.py \
        install.sh \
        uninstall.sh \
        ../icon/pombo.svg \
        ../doc/* \
        ../pombo.conf \
        ../pombo.php \
        ../pombo.py \
        ../README.md \
        ../VERSION \
"

[ -z "$1" ] && version=$(cat ../VERSION) || version="$1"
output="pombo-$version-macosx.tar.gz"
tar -cf - $files | gzip -f >$output
