# Third-party material

shioko's own code is licensed under MIT OR Apache-2.0 (`LICENSE-MIT`,
`LICENSE-APACHE`).

## Crates shioko is built with

They are not in this repository: Cargo downloads them from crates.io at the
exact versions and checksums in `Cargo.lock`. A binary built from this
repository contains their code.

- **libcrux** by Cryspen, <https://github.com/cryspen/libcrux>, Apache-2.0
  (the text is `LICENSE-APACHE`): `libcrux-chacha20poly1305`,
  `libcrux-curve25519`, `libcrux-ecdsa`, `libcrux-hacl-rs`,
  `libcrux-intrinsics`, `libcrux-macros`, `libcrux-ml-kem`, `libcrux-p256`,
  `libcrux-poly1305`, `libcrux-secrets`, `libcrux-sha2`, `libcrux-sha3`,
  `libcrux-traits`.
- **`rand` and `rand_core`**, MIT OR Apache-2.0: trait definitions only.
- **`syn`, `quote`, `proc-macro2`** (MIT OR Apache-2.0) and
  **`unicode-ident`** ((MIT OR Apache-2.0) AND Unicode-3.0) run only while
  building, inside procedural macros; none of their code is in the binary.

`patches/libcrux-platform` is not libcrux code: it is shioko's own
stand-in for libcrux's CPU-feature detection, under shioko's license.

## Test data

- **Wycheproof** test vectors, <https://github.com/C2SP/wycheproof>,
  Apache-2.0, converted by `tools/wycheproof.py`: `tests/vectors/`
  `chacha20_poly1305.txt`, `hkdf_sha256.txt`, `hmac_sha256.txt`,
  `mlkem768.txt`, `mlkem768_encaps.txt`, `x25519.txt`.
- **RFC 8448** traces, taken from the RFC by `tools/rfc8448.py`:
  `tests/vectors/rfc8448.txt`.

## RFC texts (`spec/rfc/*.txt`)

RFC 8446, 8448, 9110, 9112 and 10024, reproduced unmodified under the IETF
Trust's Legal Provisions relating to IETF Documents
(<https://trustee.ietf.org/license-info>).
