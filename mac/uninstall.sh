#!/bin/bash -e
#
# Uninstallation script for Pombo.
#

if [ $(id -ru) -ne 0 ]; then
    echo "! You need to have root rights !"
    sudo $0
    exit 0
fi

echo "\nUninstalling (verbose) ..."
rm -fv /etc/pombo.conf
[ -f /var/local/pombo ] && rm -fv /var/local/pombo
[ -f /usr/local/bin/pombo ] && rm -fv /usr/local/bin/pombo
[ -f /usr/local/sbin/pombo ] && rm -fv /usr/local/sbin/pombo
[ -f /etc/crontab ] && if [ $(grep -c "bin/pombo" /etc/crontab) != 0 ] ; then
    echo "« sed -i '/bin/pombo/d' /etc/crontab »"
    sed -i '/bin\/pombo/d' /etc/crontab
fi
echo "Done."

cat <<EOM

Thank you to have used Pombo!
If you have critics, suggestions, advices or ideas:
    https://github.com/BoboTiG/pombo

EOM

exit 0
