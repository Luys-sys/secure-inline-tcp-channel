# HKDF-SHA256 isolated test (C / OpenSSL 3)
Copy `tests/test_hkdf.c` into your project `tests/` directory.

Build: `gcc -std=c11 -Wall -Wextra -Werror tests/test_hkdf.c -o test_hkdf -lcrypto`
Run: `./test_hkdf`

This is a key-derivation *unit test*, not a complete authenticated handshake.
Fixed secret/salt are test-only; production salt/context must be session-specific and transcript-bound.
No secrets are printed. Distinct directional keys are derived with domain-separated labels.
