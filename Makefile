# NetLink build system.
#
# Targets:
#   make               - build the static and shared libraries
#   make test          - build and run every unit + integration test (C)
#   make test-bindings - run Python/Go/Rust binding tests (needs go, cargo, python3)
#   make examples      - build the example programs
#   make install       - install libs, header, and pkg-config file to $(PREFIX)
#   make dist          - package netlink-$(VERSION).tar.gz (header + libs + .pc)
#   make clean         - remove build artifacts
#
# Requires: a C11 compiler, pthreads, and OpenSSL's libcrypto (headers +
# shared library). On most Linux distros: apt install libssl-dev (or
# equivalent). macOS: brew install openssl, then point CRYPTO_CFLAGS /
# CRYPTO_LIBS at it (see the commented example below).

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -std=c11 -Wall -Wextra -O2 -fPIC
LDFLAGS ?=

# Keep in sync with NL_VERSION_* in include/netlink.h and version fields
# in bindings/python, bindings/rust.
VERSION := 1.1.1

# --- OpenSSL location ---
# Default assumes libcrypto is discoverable via pkg-config. Override
# CRYPTO_CFLAGS/CRYPTO_LIBS if your system needs an explicit path, e.g.:
#   make CRYPTO_CFLAGS="-I/opt/homebrew/opt/openssl@3/include" \
#        CRYPTO_LIBS="-L/opt/homebrew/opt/openssl@3/lib -lcrypto"
CRYPTO_CFLAGS ?= $(shell pkg-config --cflags libcrypto 2>/dev/null)
CRYPTO_LIBS   ?= $(shell pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto)

BUILD_DIR := build
SRC := src/endpoint.c src/connection.c src/channel.c src/seqbuf.c \
       src/fragment.c src/crypto.c src/util.c src/websocket.c
OBJ := $(SRC:src/%.c=$(BUILD_DIR)/%.o)

STATIC_LIB := $(BUILD_DIR)/libnetlink.a
SHARED_LIB := $(BUILD_DIR)/libnetlink.so

INCLUDES := -Iinclude -Isrc $(CRYPTO_CFLAGS)
LIBS := $(CRYPTO_LIBS) -lpthread

.PHONY: all clean test examples install

all: $(STATIC_LIB) $(SHARED_LIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(STATIC_LIB): $(OBJ)
	$(AR) rcs $@ $(OBJ)

$(SHARED_LIB): $(OBJ)
	$(CC) -shared $(OBJ) $(LIBS) -o $@

# --- tests ---
TEST_BIN_DIR := $(BUILD_DIR)/tests
TEST_CFLAGS := $(CFLAGS) -g -fsanitize=address,undefined $(INCLUDES)

.PHONY: test test-unit test-integration test-bindings
test: all test-unit test-integration

# Language-binding tests (require `make` first, plus go/cargo/python3).
test-bindings: all
	@echo "--- Python binding tests ---"
	cd bindings/python && NETLINK_LIBRARY_PATH=../../build/libnetlink.so \
		python3 tests/test_python_bindings.py
	@echo "--- Go binding tests ---"
	cd bindings/go && go vet ./... && go test -count=1 -timeout 120s ./...
	@echo "--- Rust binding tests ---"
	cd bindings/rust && cargo test

test-unit: | $(BUILD_DIR)
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(TEST_CFLAGS) -o $(TEST_BIN_DIR)/test_seqbuf src/seqbuf.c tests/test_seqbuf.c
	$(CC) $(TEST_CFLAGS) -o $(TEST_BIN_DIR)/test_crypto src/crypto.c tests/test_crypto.c $(CRYPTO_LIBS)
	$(CC) $(TEST_CFLAGS) -o $(TEST_BIN_DIR)/test_fragment src/fragment.c tests/test_fragment.c
	$(CC) $(TEST_CFLAGS) -o $(TEST_BIN_DIR)/test_channel src/channel.c src/seqbuf.c src/fragment.c tests/test_channel.c
	$(CC) $(TEST_CFLAGS) -pthread -o $(TEST_BIN_DIR)/test_connection src/connection.c src/channel.c src/seqbuf.c src/fragment.c src/crypto.c tests/test_connection.c $(CRYPTO_LIBS)
	$(CC) $(TEST_CFLAGS) -o $(TEST_BIN_DIR)/test_network_simulation src/channel.c src/seqbuf.c src/fragment.c tests/test_network_simulation.c
	$(CC) $(TEST_CFLAGS) -o $(TEST_BIN_DIR)/test_websocket src/websocket.c src/crypto.c tests/test_websocket.c $(CRYPTO_LIBS)
	@echo "--- running unit tests ---"
	$(TEST_BIN_DIR)/test_seqbuf
	$(TEST_BIN_DIR)/test_crypto
	$(TEST_BIN_DIR)/test_fragment
	$(TEST_BIN_DIR)/test_channel
	$(TEST_BIN_DIR)/test_connection
	$(TEST_BIN_DIR)/test_network_simulation
	$(TEST_BIN_DIR)/test_websocket

test-integration: | $(BUILD_DIR)
	mkdir -p $(TEST_BIN_DIR)
	$(CC) $(TEST_CFLAGS) -D_GNU_SOURCE -pthread -o $(TEST_BIN_DIR)/test_integration \
		$(SRC) tests/integration/test_integration.c $(CRYPTO_LIBS)
	$(CC) $(TEST_CFLAGS) -D_GNU_SOURCE -pthread -o $(TEST_BIN_DIR)/test_websocket_integration \
		$(SRC) tests/integration/test_websocket_integration.c $(CRYPTO_LIBS)
	@echo "--- running integration tests (real sockets) ---"
	$(TEST_BIN_DIR)/test_integration
	@echo "--- running integration tests (websocket transport) ---"
	$(TEST_BIN_DIR)/test_websocket_integration

# --- examples ---
examples: all | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/examples
	$(CC) $(CFLAGS) $(INCLUDES) examples/echo_server.c $(STATIC_LIB) $(LIBS) -o $(BUILD_DIR)/examples/echo_server
	$(CC) $(CFLAGS) $(INCLUDES) examples/echo_client.c $(STATIC_LIB) $(LIBS) -o $(BUILD_DIR)/examples/echo_client

clean:
	rm -rf $(BUILD_DIR)

PREFIX ?= /usr/local
PKGCONFIG_DIR ?= $(PREFIX)/lib/pkgconfig

# pkg-config file for downstream consumers (`pkg-config --cflags --libs netlink`).
$(BUILD_DIR)/netlink.pc: | $(BUILD_DIR)
	@echo "prefix=$(PREFIX)"                    > $@
	@echo "exec_prefix=\$${prefix}"            >> $@
	@echo "libdir=\$${exec_prefix}/lib"        >> $@
	@echo "includedir=\$${prefix}/include"     >> $@
	@echo ""                                   >> $@
	@echo "Name: netlink"                      >> $@
	@echo "Description: Secure UDP/WebSocket networking library" >> $@
	@echo "Version: $(VERSION)"                 >> $@
	@echo "Libs: -L\$${libdir} -lnetlink"      >> $@
	@echo "Libs.private: -lcrypto -lpthread"   >> $@
	@echo "Cflags: -I\$${includedir}"          >> $@

install: all $(BUILD_DIR)/netlink.pc
	install -d $(PREFIX)/lib $(PREFIX)/include $(PKGCONFIG_DIR)
	install -m 644 $(STATIC_LIB) $(SHARED_LIB) $(PREFIX)/lib/
	install -m 644 include/netlink.h $(PREFIX)/include/
	install -m 644 $(BUILD_DIR)/netlink.pc $(PKGCONFIG_DIR)/

# Self-contained tarball of everything a downstream project needs: header,
# static + shared libraries, pkg-config file, license, README, examples.
dist: all $(BUILD_DIR)/netlink.pc
	rm -rf $(BUILD_DIR)/dist
	mkdir -p $(BUILD_DIR)/dist/netlink-$(VERSION)/include
	mkdir -p $(BUILD_DIR)/dist/netlink-$(VERSION)/lib
	mkdir -p $(BUILD_DIR)/dist/netlink-$(VERSION)/lib/pkgconfig
	mkdir -p $(BUILD_DIR)/dist/netlink-$(VERSION)/examples
	cp include/netlink.h $(BUILD_DIR)/dist/netlink-$(VERSION)/include/
	cp $(STATIC_LIB) $(SHARED_LIB) $(BUILD_DIR)/dist/netlink-$(VERSION)/lib/
	cp $(BUILD_DIR)/netlink.pc $(BUILD_DIR)/dist/netlink-$(VERSION)/lib/pkgconfig/
	cp LICENSE README.md $(BUILD_DIR)/dist/netlink-$(VERSION)/
	cp examples/echo_server.c examples/echo_client.c $(BUILD_DIR)/dist/netlink-$(VERSION)/examples/
	tar -C $(BUILD_DIR)/dist -czf $(BUILD_DIR)/netlink-$(VERSION).tar.gz netlink-$(VERSION)
	@echo "Created $(BUILD_DIR)/netlink-$(VERSION).tar.gz"
