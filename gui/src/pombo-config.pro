#-------------------------------------------------
#
# Pombo GUI
# Copyleft ((C)) 2013 BoboTiG
#
# Project created by QtCreator 2013-05-09T18:30:54
#
#-------------------------------------------------

TARGET       = pombo-config
SOURCES     += main.cc mainwindow.cc
HEADERS     += mainwindow.h constants.h
FORMS       += mainwindow.ui
RESOURCES   += icon.qrc
TRANSLATIONS = l10n/fr_FR.ts

win32 {
    TARGET  += .exe
    RC_FILE += favicon.rc
}

QT += core gui widgets
