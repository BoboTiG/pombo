#!/bin/sh
#
# Simple script to test Pombo arguments.
#


n="\033[0m"
r="\033[31;03m"
v="\033[32;03m"
j="\033[33;03m"
prog=/mnt/stock/projets/pombo/pombo.py

for arg in $($prog help | egrep -o '   .*  ' | sed 's/ //g'); do
	if [ "$arg" != "check" ]; then
		$prog $arg >/dev/null
		[ $? -ne 0 ] && echo " $v!$j Erreur avec l'argument $r$arg$n $v!$n" && exit 0
		python3 $prog $arg >/dev/null
		[ $? -ne 0 ] && echo " $v!$j [python3] Erreur avec l'argument $r$arg$n $v!$n" && exit 0
	fi
done
echo "$v + Aucun problème détecté.$n"
exit 0
