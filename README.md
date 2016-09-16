Pombo
===

Theft-recovery tracking opensource software.


Links:

* [Documentation française](http://bobotig.fr/index.php?c=projets/pombo/)
* [Installation process](http://www.sebsauvage.net/pombo/installation.html)
* [FAQ](http://www.sebsauvage.net/pombo/faq.html)

Variants (could be outdated) :

* [FTP version](https://github.com/tuxmouraille/MesApps/tree/master/Pombo)
* [Google App Engine version](https://github.com/solsticedhiver/pombo_on_appengine)

What is it ?
===

Pombo can help you recover your computer in the event it's stolen.
It works on Windows, GNU/Linux and Mac OSX.

How does it work ?
===

Pombo works silently hidden in the background, sending tracking information to a webserver of your choice.

If your computer is stolen, just log into your webserver to get the lastest file uploaded by Pombo, decrypt and hand it to the police. They will have all they need to catch the thief: IP address, date/time, nearby routers, screenshot, and even a photo of his/her face if you have a webcam !

Pombo protects your privacy: Tracking information is encrypted with rock-solid GnuPG and only __*you*__ can decrypt it.

Features
===

* __Protects your privacy__: Tracking information is encrypted with a public key before sending, and only you can decrypt it with the corresponding private key.
* __Secure__: No port to open, and does not permit remote access.
* __Does not rely on third-party sites/services__: You control the client and the server. You can change servers anytime.
* __Totally free__: No software fee, no service subscription.
* __Opensource__: You can hack it, adapt it.
* __Reliable backends__: Pombo does not try to re-invent the wheel and uses solid backends (eg. no home-made encryption, uses rock-solid GnuPG)
* __Only__ takes a snapshot __if an internet connection is available__.
* __Discreet__: Uses zero CPU, zero memory and does not appear in process list when not active (not a daemon).
* Information collected:
 * System name
 * Machine vendor/type and serial number
 * Public IP address
 * Date/time
 * Information about all network interfaces (wired and wireless), including hardware address (MAC) of WiFi access point the computer is connected to.
 * Current network connections
 * Nearby routers information
 * List of all nearby WiFi access point, with their hardware address (MAC), SSID and power.
 * Screenshot
 * Webcam snaphot (if you have a webcam)

Sample report
===

Pombo sends only GnuPG encrypted zip files (for example ubuntu_20090824_155501.zip.gpg) but for practical reasons, here is an example of what they contain:

* [ubuntu\_20090824\_155501.txt](http://www.sebsauvage.net/pombo/ubuntu\_20090824\_155501.txt) : The textual report (real information is garbled for privacy reasons).
* [ubuntu\_20090824\_155501\_screenshot.png](http://www.sebsauvage.net/pombo/ubuntu\_20090824\_155501\_screenshot.png) : The screenshot.
* [ubuntu\_20090824\_155501-webcam.jpeg](http://www.sebsauvage.net/pombo/ubuntu\_20090824\_155501\_webcam.jpeg) : The webcam snapshot.

![Preview](https://tiger-222.fr/img/preview-pombo.jpg)

What is provided
===

* pombo.py (to install on the computer to track)
* pombo.php (to install on the webserver which stores tracking information)

Requirements
===

* The computer to be tracked must run GNU/Linux, Mac OSX or Windows
* Software: Python, GnuPG
* Your GPG public key
* A website where you can install the php script (php4 or php5)
* A very small GnuPG knowledge

Recommendations
===

* Enable auto-login: The thief will not be blocked by the login screen and will be less likely to wipe the harddisk.
* Copy your private key in a safe place. If you keep it only in your computer and it gets stolen, you also loose your private key, and the capacity to decrypt tracing files.
* Don't leave your private key on the computer to protect. Although the private key is itself encrypted and password-protected, it's better not let your private key in the hands of the thief.
* To protect your private files from prying eyes, use TrueCrypt, safe and reliable.
