
/*!
 * \file constants.h
 * \brief Constants for Pombo GUI.
 * \author BoboTiG
 * \date 2013.06.03
 *
 * Copyleft ((C)) 2013 BoboTiG
 */


#ifndef CONSTANTS_H
#define CONSTANTS_H


static const char POMBOGUI_VERSION[] = "2013.07-11 rev0";

#ifdef _WIN32
    static const char POMBO_FOLDER[] = "C:\\pombo";
    static const char CONFIG_FILE[]  = "C:\\pombo\\pombo.conf";
#else
    static const char CONFIG_FILE[] = "/etc/pombo.conf";
    static const char CRON_FILE[]   = "/etc/cron.d/pombo";
    static const char CRON_LINE[]   = "*/%d * * * * root /usr/local/bin/pombo\n";
    static const char CMD_LIST[]    = "predefined-cmd.conf";
#endif

// Site web officiel
static const char WEBSITE[] = "http://bobotig.fr/?c=projets/pombo/&ref=pombo-config";

// Délais (en minutes)
static const int TIME_NORMAL_MIN = 15;
static const int TIME_NORMAL_MAX = 60;

// Commandes par défaut
#ifdef _WIN32
    static const char CMD_NETWORK[]    = "ipconfig /all";
    static const char CMD_WIRELESS[]   = "netsh wlan show all";
    static const char CMD_TRACERT[]    = "tracert -d www.example.org";
    static const char CMD_NETTRAFIC[]  = "netstat -n";
#else
    static const char CMD_NETWORK[]    = "/sbin/ifconfig -a";
    static const char CMD_WIRELESS[]   = "/sbin/iwlist scanning";
    static const char CMD_TRACERT[]    = "/usr/bin/traceroute -q1 -n www.example.com";
    static const char CMD_NETTRAFIC[]  = "/bin/netstat -putn";
#endif


#endif // CONSTANTS_H
