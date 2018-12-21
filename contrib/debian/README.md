
Debian
====================
This directory contains files used to package blibraryd/blibrary-qt
for Debian-based Linux systems. If you compile blibraryd/blibrary-qt yourself, there are some useful files here.

## blibrary: URI support ##


blibrary-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install blibrary-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your blibraryqt binary to `/usr/bin`
and the `../../share/pixmaps/blibrary128.png` to `/usr/share/pixmaps`

blibrary-qt.protocol (KDE)

