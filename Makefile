LIBS=$(shell pkg-config --libs glib-2.0) -lz
CFLAGS=$(shell pkg-config --cflags glib-2.0) -O2 -Wall

all: pmg-log-tracker

pmg-log-tracker: pmg-log-tracker.c
	gcc $< -o $@ ${CFLAGS} ${LIBS}



