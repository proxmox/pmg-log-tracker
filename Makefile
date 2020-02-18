include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=pmg-log-tracker
BUILDDIR ?= ${PACKAGE}-${DEB_VERSION_UPSTREAM}

GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_${DEB_BUILD_ARCH}.deb
DSC=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}.dsc

all: ${DEB}

.PHONY: ${BUILDDIR}
${BUILDDIR}: src
	rm -rf ${BUILDDIR} ${BUILDDIR}.tmp
	mkdir ${BUILDDIR}.tmp
	cp -a src ${BUILDDIR}.tmp/src
	cp Cargo.toml ${BUILDDIR}.tmp/
	cp -a debian ${BUILDDIR}.tmp/debian
	echo "git clone git://git.proxmox.com/git/pmg-log-tracker.git\\ngit checkout ${GITVERSION}" > ${BUILDDIR}.tmp/debian/SOURCE
	mv ${BUILDDIR}.tmp ${BUILDDIR}

.PHONY: deb
deb ${DEB}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}

.PHONY: dsc
dsc ${DSC}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -rfakeroot -S -us -uc -d
	lintian ${DSC}

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

.PHONY: upload
upload: ${DEB} ${DBG_DEB}
	tar cf - ${DEB} ${DBG_DEB}| ssh repoman@repo.proxmox.com -- upload --product pmg --dist stretch --arch ${DEB_BUILD_ARCH}

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	rm -rf *.deb ${PACKAGE}-* *.buildinfo *.changes *.dsc ${PACKAGE}_*.tar.gz
	find . -name '*~' -exec rm {} ';'
