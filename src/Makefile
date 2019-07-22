DESTDIR=

LIBS=$(shell pkg-config --libs glib-2.0) -lz
CFLAGS=$(shell pkg-config --cflags glib-2.0) -O2 -Wpedantic

all: pmg-log-tracker

pmg-log-tracker: pmg-log-tracker.c
	gcc $< -o $@ ${CFLAGS} ${LIBS}

.PHONY: install
install: pmg-log-tracker
	install -d ${DESTDIR}/usr/bin
	install -m 0755 pmg-log-tracker ${DESTDIR}/usr/bin/

.PHONY: clean distclean
distclean: clean
clean:
	rm -rf pmg-log-tracker
	find . -name '*~' -exec rm {} ';'
