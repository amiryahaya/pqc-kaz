# Makefile for KAZ-SIGN Elixir NIF

# Erlang paths
ERL_INCLUDE_PATH ?= $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
ERL_INTERFACE_INCLUDE_PATH ?= $(shell erl -eval 'io:format("~s", [code:lib_dir(erl_interface, include)])' -s init stop -noshell)
ERL_INTERFACE_LIB_PATH ?= $(shell erl -eval 'io:format("~s", [code:lib_dir(erl_interface, lib)])' -s init stop -noshell)

# KAZ-SIGN source paths (relative to bindings/elixir)
KAZ_ROOT = ../..
KAZ_INCLUDE = $(KAZ_ROOT)/include
KAZ_SRC = $(KAZ_ROOT)/src/internal

# OpenSSL paths (platform detection)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS with Homebrew
    OPENSSL_PREFIX ?= $(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)
else
    # Linux
    OPENSSL_PREFIX ?= /usr
endif

OPENSSL_INCLUDE = $(OPENSSL_PREFIX)/include
OPENSSL_LIB = $(OPENSSL_PREFIX)/lib

# Compiler settings
CC ?= cc
CFLAGS = -O3 -Wall -Wextra -fPIC -std=c11
CFLAGS += -I$(ERL_INCLUDE_PATH)
CFLAGS += -I$(KAZ_INCLUDE)
CFLAGS += -I$(KAZ_SRC)
CFLAGS += -I$(OPENSSL_INCLUDE)
CFLAGS += -DKAZ_SECURITY_LEVEL=128

# Linker settings
LDFLAGS = -shared
LDFLAGS += -L$(OPENSSL_LIB)
LIBS = -lcrypto

# Platform-specific settings
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -dynamiclib -undefined dynamic_lookup
    SO_EXT = so
else
    SO_EXT = so
endif

# Output
PRIV_DIR = priv
NIF_SO = $(PRIV_DIR)/kaz_sign_nif.$(SO_EXT)

# Source files
NIF_SRC = c_src/kaz_sign_nif.c
KAZ_SRC_FILES = $(KAZ_SRC)/sign.c $(KAZ_SRC)/nist_wrapper.c $(KAZ_SRC)/kdf.c $(KAZ_SRC)/security.c

# Object files
NIF_OBJ = c_src/kaz_sign_nif.o
KAZ_OBJ = c_src/sign.o c_src/nist_wrapper.o c_src/kdf.o c_src/security.o

.PHONY: all clean

all: $(PRIV_DIR) $(NIF_SO)

$(PRIV_DIR):
	mkdir -p $(PRIV_DIR)

$(NIF_SO): $(NIF_OBJ) $(KAZ_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

c_src/kaz_sign_nif.o: c_src/kaz_sign_nif.c
	$(CC) $(CFLAGS) -c -o $@ $<

c_src/sign.o: $(KAZ_SRC)/sign.c
	$(CC) $(CFLAGS) -c -o $@ $<

c_src/nist_wrapper.o: $(KAZ_SRC)/nist_wrapper.c
	$(CC) $(CFLAGS) -c -o $@ $<

c_src/kdf.o: $(KAZ_SRC)/kdf.c
	$(CC) $(CFLAGS) -c -o $@ $<

c_src/security.o: $(KAZ_SRC)/security.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(NIF_SO) $(NIF_OBJ) $(KAZ_OBJ)
	rm -rf $(PRIV_DIR)
