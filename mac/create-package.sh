#!/bin/bash -e
#
# Package creation for Pombo (Mac OSX).
#

[ -z "$1" ] && version=$(cat ../VERSION) || version="$1"
output="pombo-$version.dmg"
src=~/Desktop/pombo
tmp="$src/tmp"

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

[ -f $output ] && rm -rf $output
[ -d "$tmp" ] && rm -rf "$tmp"
mkdir "$tmp"
mkdir "$tmp/data"
cp $files "$tmp/data/"
cp Install "$tmp/"

bash create-dmg.sh --window-size 360 170 \
    --icon-size 114 \
    --volname "Pombo" \
    $output \
    "$tmp"
rm -rf "$tmp"
