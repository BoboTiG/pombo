#!/bin/sh
#
# Installation script for Pombo.
#

if [ $(id -ru) -ne 0 ]; then
	echo "! You need to have root rights !"
	su root -c $0
	exit 0
fi

echo "\nInstalling (verbose) ..."
install -v pombo.conf /etc
install -v pombo.py /usr/local/bin
chmod 600 -v /etc/pombo.conf
chmod +x -v /usr/local/bin/pombo.py
if test -f /etc/crontab ; then
	if [ $(grep -c "/usr/local/bin/pombo.py" /etc/crontab) != 0 ] ; then
		echo "« sed -i '\/usr\/local\/bin\/pombo.py/d' /etc/crontab »"
		sed -i '\/usr\/local\/bin\/pombo.py/d' /etc/crontab
	fi
else
	echo "« touch /etc/crontab »"
	touch /etc/crontab
	chmod 644 -v /etc/crontab
fi
echo "« */15 * * * * root /usr/local/bin/pombo.py >>/etc/crontab »"
echo "*/15 * * * * root /usr/local/bin/pombo.py" >>/etc/crontab
[ -f /var/local/pombo ] && rm -fv /var/local/pombo
echo "Done."

echo "\nChecking dependancies ..."
ok=1
for package in python gpg ifconfig iwlist traceroute import streamer pngnq; do
	test=$(which ${package})
	[ $? != 0 ] && echo " ! ${package} needed but not installed." && ok=0
done
case ${ok} in
	1) echo "Done." ;;
	*) 
		echo "Please install necessary tools before continuing."
		echo " i.e.: python gnupg net-tools iw traceroute imagemagick streamer pngnq"
	;;
esac

cat <<EOM

Thank you to use Pombo!
Then you will need to:
	1 - import your GnuPG keyID
	2 - tune options into /etc/pombo.conf
	3 - tune variables into pombo.php
	4 - copy pombo.php to your server(s) (both PHP versions 4 & 5 supported)
And do not forget to write somewhere in security your computer Serial Number.

EOM
exit 0
