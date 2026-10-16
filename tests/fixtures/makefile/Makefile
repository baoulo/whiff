# Harbour build
PREFIX ?= /usr/local
CARGO := cargo
VERSION = 2.3.0

include config.mk

.PHONY: all build test install clean

all: build

build:
	$(CARGO) build --release

test: build
	$(CARGO) test

install: build
	install -m 755 target/release/harbourd $(PREFIX)/bin/

%.o: %.c
	$(CC) -c $< -o $@

clean:
	rm -rf target
