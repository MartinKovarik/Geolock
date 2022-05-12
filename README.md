# Geolock
Plugin for SpamAssassin for blocking e-mails based on the geolocation of the sender using a IP2Location database. 

This plugin checks e-mail headers and blocks e-mails from selected countries based on the geolocation of the sender. 
These countries can be specified by the user in the .cf file. By default, the furthermost Received: header is taken as the origin (only external non-trusted and non-reserved IP addresses are taken into account). If the user suspects that the e-mail has spoofed Received: headers, he can change a setting in the Geolock.cf file so that the first external non-trusted non-reserved IP address is taken as the source. The plugin requires a downloaded IP2Location database.


Installing: Copy Geolock.pm and Geolock.cf into /etc/mail/spamassassin (or whatever directory you use for your plugins), add "loadplugin Mail::SpamAssassin::Plugin::Geolock Geolock.pm" into init.pre file and download any IP2Location database and put it at "/etc/mail/spamassassin/DB/IP2LOCATION.BIN" (or edit the Geolock.pm file to change it to whatever you desire).
