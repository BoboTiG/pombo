;
; Package creation for Pombo (Microsoft Windows).
;

#define MyAppName "Pombo"
#define MyAppVersion "1.0.3"
#define MyAppPublisher "JMSinfo SAS"
#define MyAppURL "http://pombo.jmsinfo.co"

; Constante pour créer un installeur personnalisé.
; Ceci permet de déployer facilement le logiciel chez un client.
; ex : "-fanny" pour pombo-fanny.conf, POSTINSTALL-fanny.txt et pombo-$version-fanny_setup.exe
; ex : "-CL00057-lenovo" pour pombo-CL00057-lenovo.conf, POSTINSTALL-CL00057-lenovo.txt et pombo-$version-CL00057-lenovo_setup.exe
; Laisser vide par défaut.
#define Custom ""

; Version présentent dans cet installeur
#define PythonVersion "2.7.5"
#define GnuPGVersion "1.4.13"

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{D24DCF9D-1F2E-4846-A4DF-0A41E13E4472}
AppCopyright=Copyleft 2012-2015 {#MyAppPublisher}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppReadmeFile={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName=C:\pombo
DefaultGroupName={#MyAppName}
DisableDirPage=yes
DisableReadyPage=yes
DisableProgramGroupPage=yes
InfoAfterFile=POSTINSTALL{#Custom}.txt
LicenseFile=..\doc\LICENSE
OutputBaseFilename=pombo-{#MyAppVersion}{#Custom}_setup
SetupIconFile=..\icon\pombo.ico
WizardImageFile=..\icon\pombo-wizard.bmp
WizardSmallImageFile=..\icon\pombo-wizard-small.bmp
; Empêcher l'apparition du programme dans Ajouter/Suprrimer des programmes
CreateUninstallRegKey=no
Uninstallable=no
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[CustomMessages]
; Français
french.marque_title=Mode furtif
french.marque_texte=Sélectionnez le modèle qui correspond le plus à votre matériel afin de personnaliser le mode furtif.
french.marque_memo=Modèle sélectionné pour le mode furtif :
french.type_full=Installation complète
french.type_custom=Installation personnalisée
french.install_wlandump=WLAN Dump pour lister les signaux Wi-Fi sous Windows XP
french.testing=Test du bon fonctionnement de Pombo

; Anglais
english.marque_title=Stealth mode
english.marque_texte=Select the model which best correspond with your hardware to customise the stealth mode.
english.marque_memo=Selected model for the stealth mode:
english.type_full=Full installation
english.type_custom=Custom installation
english.install_wlandump=WLAN Dump for listing wireless networks on Windows XP
english.testing=Test Pombo

[Types]
Name: "full"; Description: "{cm:type_full}"
Name: "custom"; Description: "{cm:type_custom}"; Flags: iscustom

[Components]
Name: "program"; Description: "Pombo {#MyAppVersion}"; Types: full custom; Flags: fixed
Name: "gpg"; Description: "GnuPG {#GnuPGVersion}"; Types: full
Name: "xp"; Description: "{cm:install_wlandump}"; Types: custom

[Dirs]
Name: "{app}"; Attribs: hidden system
Name: "{app}\bin"
Name: "{app}\doc"
Name: "{app}\python"

[Files]
Source: "bin\gpg.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "bin\iconv.dll"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "bin\wlan.exe"; DestDir: "{app}\bin"; Flags: ignoreversion; Components: xp
Source: "bin\wlan-dump.bat"; DestDir: "{app}\bin"; Flags: ignoreversion; Components: xp
Source: "..\doc\CREDITS"; DestDir: "{app}\doc"; Flags: ignoreversion
Source: "..\doc\INSTALL"; DestDir: "{app}\doc"; Flags: ignoreversion
Source: "..\doc\LICENSE"; DestDir: "{app}\doc"; Flags: ignoreversion
Source: "..\pombo{#Custom}.conf"; DestDir: "{app}"; DestName: "pombo.conf"; Flags: confirmoverwrite; Attribs: hidden system
Source: "..\pombo.php"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\pombo.py"; DestDir: "{app}"; Flags: ignoreversion; Attribs: hidden system
Source: "pombo.vbs"; DestDir: "{pf}\{code:GetTheMarkLower}"; DestName: "{code:GetTheMarkLower}-config.vbs"; Flags: ignoreversion; Attribs: hidden system
Source: "empty"; DestDir: "{app}"; DestName: "{code:GetTheMarkLower}.stealth"; Flags: ignoreversion; Attribs: hidden system
Source: "Pombo - Add IP.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "Pombo - Test.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "Pombo - Update.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "python\*"; DestDir: "{app}\python"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\doc\REQUIREMENTS"; DestDir: "{app}\doc"; Flags: ignoreversion
Source: "..\VERSION"; DestDir: "{app}\doc"; Flags: ignoreversion

[Registry]
; Lancement de Pombo au démarrage
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{code:GetTheMark} Configuration"; ValueData: "{pf}\{code:GetTheMarkLower}\{code:GetTheMarkLower}-config.vbs"

[Code]
{ Ajout de la page pour sélectionner le modèle }
#include "getmark.iss"

[Run]
Filename: "{app}\Pombo - Test.bat"; Parameters: "/silent"; Description: "{cm:testing}"; Flags: postinstall
