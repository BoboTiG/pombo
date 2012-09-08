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
[ -f /var/local/pombo ] && rm -fv /var/local/pombo
if -f /usr/local/bin/pombo.py; then
	# Retro-compatibility (version <= 0.0.9)
	rm -fv /usr/local/bin/pombo.py
	echo "« sed -i '\/usr\/local\/bin\/pombo.py/d' /etc/crontab »"
	sed -i '\/usr\/local\/bin\/pombo.py/d' /etc/crontab
else
	rm -fv /usr/local/bin/pombo
	echo "« sed -i '\/usr\/local\/bin\/pombo/d' /etc/crontab »"
	sed -i '\/usr\/local\/bin\/pombo/d' /etc/crontab
fi
echo "Done."

cat <<EOM

Thank you to have used Pombo!
If you have critics, suggestions, advices or ideas:
	bobotig@gmail.com

EOM

exit 0
