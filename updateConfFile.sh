#!/bin/bash

# Aide
bold=$(tput bold)
normal=$(tput sgr0)
oldSaves=120	# Nombre de jours pour l'effacement des anciennes sauvegardes

if [ "$#" -lt 5 ]; then
	echo
	echo "${bold}Mise à jour du fichier de configuration de pombo${normal}"
	echo
	echo "Paramètre manquant."
	echo "Utilisez --help pour plus d'informations"
	exit 1
fi

if [ $1 = "--help" ] || [ $1 = "-h" ]; then
	echo
	echo "${bold}Mettre à jour des valeurs danss le fihier de configuration de Pombo${normal}"
	echo
	echo "Utilisation : updateConfFile [CHAMP] -i [NEW_FILE] -o [OLD_FILE]."
	echo "Le champ [CHAMP] sera mis à jour de [NEW_FILE] vers [OLD_FILE]."

	echo
	echo "${bold}État de sortie :${normal}"
	echo " 0	en cas de succès"
	echo " 1	en cas d'échec"
 
	exit 0
fi

CHAMP=$1
if [ $2 = '-i' ]; then
	NEW_FILE=$3
	if [ $4 = '-o' ]; then
		OLD_FILE=$5
	fi
else
    if [ $2 = '-o' ]; then
	OLD_FILE=$3
	if [ $4 = '-i' ]; then
		NEW_FILE=$5
	fi
    fi
fi

echo $CHAMP
echo $OLD_FILE
echo $NEW_FILE

if ! grep -q ${CHAMP}= ${OLDFILE} ; then
	exit 0
fi

if [ -f $OLD_FILE ] && [ -f $NEW_FILE ] && [ ! -z $CHAMP ]; then
	STRING=`grep ${CHAMP}= ${NEW_FILE} | cut -d= -f2-`
	STRING="${STRING//'/'/'\/'}"
	sed -i "s/\(${CHAMP}=\).*/\1${STRING}/" ${OLD_FILE}
	exit 0
else
	echo "Veuillez spécifier des fichiers valides"
	echo "Utilisez --help pour plus d'informations"
	exit 1
fi
