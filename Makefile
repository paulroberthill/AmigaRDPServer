# RDP server for AmigaOS 3.x, with a Linux prototype host.
#   make            build ./rdpserver (Linux) and build/rdpserver (Amiga, 68060)
#   make test       Linux: crypto tests + end-to-end test over TCP
#   make test68k    68k code under vamos: crypto tests + end-to-end test over pipes
#   make newkey     regenerate the server RSA key / certificate

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu99 -Wall -Wextra

AMIGA_CC     = /opt/amiga/bin/m68k-amigaos-gcc
# libnix: small binaries, and it honours __stack (newlib does not)
AMIGA_CFLAGS = -mcrt=nix20 -m68060 -O2 -std=gnu99 -Wall -Wextra -Wno-pointer-sign
# own volume dir: a killed vamos leaves its temporary RAM: volume behind,
# which makes the next run refuse to start
VAMOS        = .venv/bin/vamos --vols-base-dir $(CURDIR)/build/vamos-vols

CORE   = src/rdp.c src/cliprdr.c src/login.c src/rle.c src/sec.c src/srvkey.c src/keygen.c \
         src/md5.c src/sha1.c src/rc4.c src/bignum.c
CRYPTO = src/md5.c src/sha1.c src/rc4.c src/bignum.c
HDRS   = src/rdp.h src/cliprdr.h src/login.h src/rle.h src/sec.h src/crypto.h src/stream.h \
         src/serverkey.h src/keygen.h src/font5x7.h
# Build-time key for the Linux and native test hosts (the Amiga host
# generates its own on first run, so no key is ever compiled into it).
HOSTKEY = src/posix/hostkey.c
TP     = src/testpattern.c src/testpattern.h src/font5x7.h

all: rdpserver build/rdpserver

rdpserver: $(CORE) $(TP) src/posix/main.c $(HOSTKEY) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(CORE) src/testpattern.c src/posix/main.c $(HOSTKEY)

AMIGA_SRC = src/amiga/main.c src/amiga/ftxt.c src/amiga/beep.c src/amiga/scan.c
build/rdpserver: $(CORE) $(AMIGA_SRC) src/amiga/keymap.h src/amiga/ftxt.h src/amiga/beep.h src/amiga/scan.h $(HDRS) | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -o $@ $(CORE) $(AMIGA_SRC)

# Generated once per checkout so every checkout has its own key.
$(HOSTKEY):
	python3 -I tools/genkey.py $@

newkey:
	python3 -I tools/genkey.py $(HOSTKEY)

build:
	mkdir -p build

tests/crypto_vectors.h: tests/crypto_vectors.py
	python3 -I tests/crypto_vectors.py $@

test_crypto: tests/test_crypto.c tests/crypto_vectors.h $(CRYPTO) src/crypto.h
	$(CC) $(CFLAGS) -o $@ tests/test_crypto.c $(CRYPTO)

build/test_crypto.68k: tests/test_crypto.c tests/crypto_vectors.h $(CRYPTO) src/crypto.h | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -o $@ tests/test_crypto.c $(CRYPTO)

build/pipehost.68k: tests/pipehost.c $(CORE) $(TP) $(HOSTKEY) $(HDRS) | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -DHAVE_HOSTKEY -o $@ tests/pipehost.c $(CORE) src/testpattern.c $(HOSTKEY)

build/pipehost: tests/pipehost.c $(CORE) $(TP) $(HOSTKEY) $(HDRS) | build
	$(CC) $(CFLAGS) -DHAVE_HOSTKEY -o $@ tests/pipehost.c $(CORE) src/testpattern.c $(HOSTKEY)

build/test_ftxt: tests/test_ftxt.c src/amiga/ftxt.c src/amiga/ftxt.h | build
	$(CC) $(CFLAGS) -o $@ tests/test_ftxt.c src/amiga/ftxt.c

build/test_ftxt.68k: tests/test_ftxt.c src/amiga/ftxt.c src/amiga/ftxt.h | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -o $@ tests/test_ftxt.c src/amiga/ftxt.c

build/test_beep.68k: tests/test_beep.c src/amiga/beep.c src/amiga/beep.h | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -o $@ tests/test_beep.c src/amiga/beep.c

build/test_scan: tests/test_scan.c src/amiga/scan.c src/amiga/scan.h | build
	$(CC) $(CFLAGS) -o $@ tests/test_scan.c src/amiga/scan.c

build/test_scan.68k: tests/test_scan.c src/amiga/scan.c src/amiga/scan.h | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -o $@ tests/test_scan.c src/amiga/scan.c

build/test_keygen: tests/test_keygen.c src/keygen.c src/keygen.h src/bignum.c | build
	$(CC) $(CFLAGS) -o $@ tests/test_keygen.c src/keygen.c src/bignum.c

build/test_keygen.68k: tests/test_keygen.c src/keygen.c src/keygen.h src/bignum.c | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -o $@ tests/test_keygen.c src/keygen.c src/bignum.c

build/test_rle: tests/test_rle.c src/rle.c src/rle.h | build
	$(CC) $(CFLAGS) -o $@ tests/test_rle.c src/rle.c

build/test_rle.68k: tests/test_rle.c src/rle.c src/rle.h | build
	$(AMIGA_CC) $(AMIGA_CFLAGS) -o $@ tests/test_rle.c src/rle.c

test: test_crypto build/test_rle build/test_ftxt build/test_scan build/test_keygen rdpserver
	./test_crypto
	python3 -I tests/test_keygen.py build/test_keygen 10
	build/test_ftxt
	build/test_scan
	python3 -I tests/test_rle.py build/test_rle
	@echo "== saved credentials (password in Client Info), full suite"
	python3 -I tests/testclient.py --password 'Amiga-1200!' --spawn ./rdpserver -P 'Amiga-1200!'
	@echo "== password typed at the login prompt, after one wrong attempt"
	python3 -I tests/testclient.py --type 'Amiga-1200!' --flood 0 --spawn ./rdpserver -P 'Amiga-1200!'
	@echo "== three wrong passwords"
	python3 -I tests/testclient.py --wrong --flood 0 --spawn ./rdpserver -P secret
	@echo "== no password (-n), with a key generated at startup (-k)"
	python3 -I tests/testclient.py --flood 0 --spawn ./rdpserver -n -k

# vamos: python3 -m venv .venv && .venv/bin/pip install amitools==0.8.1 machine68k==0.3.0
test68k: build/test_crypto.68k build/test_rle.68k build/test_ftxt.68k build/test_beep.68k build/test_scan.68k build/pipehost.68k
	rm -rf build/vamos-vols
	$(VAMOS) -C 68020 build/test_crypto.68k
	rm -rf build/vamos-vols
	python3 -I tests/test_rle.py $(VAMOS) -q -C 68020 build/test_rle.68k
	rm -rf build/vamos-vols
	$(VAMOS) -q -C 68020 build/test_ftxt.68k
	rm -rf build/vamos-vols
	$(VAMOS) -q -C 68020 build/test_beep.68k
	rm -rf build/vamos-vols
	$(VAMOS) -q -C 68020 -m 8192 build/test_scan.68k
	rm -rf build/vamos-vols
	python3 -I tests/testclient.py --files build/pipe --password secret \
	    --spawn $(VAMOS) -q -C 68020 -m 8192 \
	    build/pipehost.68k build/pipe/c2s build/pipe/s2c 16 wire pw=secret

# Key generation as 68k code: slow under vamos (minutes), so separate.
test68k-keygen: build/test_keygen.68k
	rm -rf build/vamos-vols
	python3 -I tests/test_keygen.py $(VAMOS) -q -C 68020 build/test_keygen.68k 1

clean:
	rm -rf rdpserver test_crypto build

.PHONY: all test test68k test68k-keygen clean newkey
