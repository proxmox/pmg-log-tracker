PACKAGE=pmg-log-tracker
PKGVER=1.0
PKGREL=1

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
GITVERSION:=$(shell cat .git/refs/heads/master)

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_${ARCH}.deb

LIBS=$(shell pkg-config --libs glib-2.0) -lz
CFLAGS=$(shell pkg-config --cflags glib-2.0) -O2 -Wpedantic

all: ${DEB}

pmg-log-tracker: pmg-log-tracker.c
	gcc $< -o $@ ${CFLAGS} ${LIBS}

.PHONY: deb
deb ${DEB}: pmg-log-tracker
	rm -f *.deb
	rm -rf build
	install -D -m 0755 pmg-log-tracker build/usr/bin/pmg-log-tracker
	cp -a debian build/debian
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

.PHONY: upload
upload: ${DEB} ${DBG_DEB}
	tar cf - ${DEB} ${DBG_DEB}| ssh repoman@repo.proxmox.com -- upload --product pmg --dist stretch --arch ${ARCH}

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	rm -rf build *.deb pmg-log-tracker *.buildinfo *.changes
	find . -name '*~' -exec rm {} ';'
