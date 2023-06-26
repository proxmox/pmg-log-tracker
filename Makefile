include /usr/share/dpkg/default.mk

PACKAGE=pmg-log-tracker

DEB=$(PACKAGE)_$(DEB_VERSION)_$(DEB_BUILD_ARCH).deb
DBG_DEB=$(PACKAGE)-dbgsym_$(DEB_VERSION)_$(DEB_BUILD_ARCH).deb
DSC=rust-$(PACKAGE)_$(DEB_VERSION).dsc

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
	rm -rf debian/control
	debcargo package \
	  --config debian/debcargo.toml \
	  --changelog-ready \
	  --no-overlay-write-back \
	  --directory build \
	  $(PACKAGE) \
	  $(shell dpkg-parsechangelog -l debian/changelog -SVersion | sed -e 's/-.*//')
	rm build/Cargo.lock
	find build/debian -name "*.hint" -delete
	cp build/debian/control debian/control
	echo "git clone git://git.proxmox.com/git/pmg-log-tracker.git\\ngit checkout $(shell git rev-parse HEAD)" > build/debian/SOURCE

.PHONY: deb
deb: $(DEB)
$(DEB) $(DBG_DEB): build
	cd build; dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: dsc
dsc: $(DSC)
	$(MAKE) $(DSC)
	lintian $(DSC)

$(DSC): build
	cd build; dpkg-buildpackage -S -us -uc -d

.PHONY: sbuild
sbuild: $(DSC)
	sbuild $(DSC)

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $(DEB)

.PHONY: upload
upload: $(DEB) $(DBG_DEB)
	tar cf - $(DEB) $(DBG_DEB)| ssh -X repoman@repo.proxmox.com -- upload --product pmg --dist bullseye --arch $(DEB_BUILD_ARCH)

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	rm -rf $(PACKAGE)-[0-9]*/ build/
	rm -f *.deb *.buildinfo *.changes *.dsc rust-$(PACKAGE)*.tar* *build
