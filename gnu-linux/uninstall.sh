#!/bin/sh
#
# Uninstallation script for Pombo.
#

if [ $(id -ru) -ne 0 ]; then
	echo "! You need to have root rights !"
	su root -c $0
	exit 0
fi

echo "\nUninstalling (verbose) ..."
rm -fv /etc/pombo.conf
rm -fv /usr/local/bin/pombo
[ -f /var/local/pombo ] && rm -fv /var/local/pombo
echo "« sed -i '\/usr\/local\/bin\/pombo/d' /etc/crontab »"
sed -i '\/usr\/local\/bin\/pombo/d' /etc/crontab
echo "Done."

cat <<EOM

Thank you to have used Pombo!
If you have critics, suggestions, advices or ideas:
	bobotig@gmail.com

EOM

exit 0
