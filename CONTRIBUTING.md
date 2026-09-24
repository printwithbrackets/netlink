# Contributing to NetLink

Thanks for considering a contribution. This project prioritizes
correctness and security over speed of development -- please read the
notes below before opening a PR.

## Ground rules

1. **Security first, speed second.** If a change trades away a security
   property (authentication, replay protection, input validation on
   attacker-controlled fields) for performance, it needs explicit
   discussion in the PR description, not just a benchmark number.
2. **No bug is too small to fix immediately.** If you find a bug while
   working on something else, fix it in the same PR (with its own test)
   rather than filing it for later, unless it's genuinely out of scope.
3. **Every change needs a test.** Bug fixes need a regression test that
   fails without the fix. New features need unit tests for the logic and,
   where relevant, an integration test exercising a real client+server
   pair over actual sockets (see `tests/integration/`).
4. **Hand-rolled crypto is not welcome.** All cryptographic primitives
   (AES-GCM, X25519, HKDF, HMAC) go through OpenSSL's EVP API
   (`src/crypto.c`). Do not add a second crypto implementation, even a
   "simple" one, even for a non-critical path.

## Building and testing

```sh
make CRYPTO_CFLAGS="..." CRYPTO_LIBS="..."   # see README for platform-specific flags
make test                                     # unit tests + real-socket integration tests
```

Unit tests build with `-fsanitize=address,undefined`. A change that
introduces a memory or undefined-behavior issue should fail loudly under
these sanitizers -- please don't disable them to get a PR green.

### Adding a test

- Pure logic (sequence buffers, fragmentation, channel state machine,
  crypto primitives): add to the relevant `tests/test_*.c` file. These use
  the tiny header-only framework in `tests/test_framework.h` --
  `TEST(name) { ... ASSERT_EQ(a, b); ... }`, registered in `main()` via
  `RUN_TEST(name)`.
- End-to-end behavior (handshake, real delivery-mode semantics, discovery):
  add to `tests/integration/test_integration.c`, which spins up a real
  server and client over loopback UDP.

## Code style

- C11, portable POSIX (the WIN32 branches in `socket_compat.h` are
  written but not CI-tested here -- see the file header). Please don't
  introduce compiler-specific extensions.
- No warnings. Every source file here compiles clean under
  `-Wall -Wextra`; new code should too.
- Comments explain *why*, not *what* -- especially for anything
  security-relevant (nonce construction, replay windows, cookie
  verification). If you had to think hard about why an ordering of
  operations matters, write that reasoning down.

## Language bindings

The C core (`src/`) is the single source of truth for the wire protocol.
Bindings (`bindings/python`, `bindings/go`, `bindings/rust`) should be
thin wrappers over the stable C ABI in `include/netlink.h` -- they must
not reimplement any protocol logic. If a binding's struct layout doesn't
match the C header, that's a bug in the binding, not a reason to add
protocol logic on the binding side.

The Python, Go, and Rust bindings are all built and tested against the
compiled C library as part of this repository's own test suite (`make
test-bindings`, also run in CI). If you change a binding, run its native
test command:

```sh
# from the repository root, after `make`
make test-bindings
# or individually:
cd bindings/python && NETLINK_LIBRARY_PATH=../../build/libnetlink.so python3 tests/test_python_bindings.py
cd bindings/go     && go test ./...
cd bindings/rust   && cargo test
```

## Reporting security issues

If you find a vulnerability (a way to bypass authentication, forge a
packet, cause unbounded memory growth from attacker-controlled input,
etc.), please open an issue describing it. Given this is a reference
implementation rather than a hardened production deployment used at
scale, there isn't yet a formal private disclosure process -- use your
judgment about severity, and feel free to flag in the issue title if you
think it warrants care in how details are shared.

## Pull request checklist

- [ ] Builds warning-free (`make`)
- [ ] `make test` passes, including any new tests
- [ ] New/changed public API documented in `include/netlink.h`'s comments
- [ ] If the wire format changed: `NL_PROTOCOL_VERSION` bumped and the
      change noted in the PR description
- [ ] If a security-relevant assumption changed: called out explicitly
