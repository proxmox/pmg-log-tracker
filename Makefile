include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=pmg-log-tracker

GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_${DEB_BUILD_ARCH}.deb
DSC=rust-${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}.dsc

ifeq ($(BUILD_MODE), release)
CARGO_BUILD_ARGS += --release
COMPILEDIR := target/release
else
COMPILEDIR := target/debug
endif

all: cargo-build $(SUBDIRS)

.PHONY: cargo-build
cargo-build:
	cargo build $(CARGO_BUILD_ARGS)

.PHONY: build
build:
	rm -rf build
	debcargo package \
	  --config debian/debcargo.toml \
	  --changelog-ready \
	  --no-overlay-write-back \
	  --directory build \
	  $(PACKAGE) \
	  $(shell dpkg-parsechangelog -l debian/changelog -SVersion | sed -e 's/-.*//')
	rm build/Cargo.lock
	find build/debian -name "*.hint" -delete

.PHONY: deb
deb: $(DEB)
$(DEB): build
	cd build; dpkg-buildpackage -b -us -uc --no-pre-clean --build-profiles=nodoc
	lintian $(DEB)

.PHONY: dsc
dsc: $(DSC)
$(DSC): build
	cd build; dpkg-buildpackage -S -us -uc -d -nc
	lintian $(DSC)

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
