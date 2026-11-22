# Third-party material

shioko's own code is licensed under MIT OR Apache-2.0 (`LICENSE-MIT`,
`LICENSE-APACHE`). This repository also contains the following, each under
its own terms.

## Vendored crates (`vendor/`)

`tools/vendor.sh` fills `vendor/` from `Cargo.lock`. The exact versions are
in `Cargo.lock`.

- **libcrux** by Cryspen, <https://github.com/cryspen/libcrux>, licensed
  under Apache-2.0, whose text is `LICENSE-APACHE` at the top of this
  repository. These crates are compiled into shioko and stored unmodified:
  `libcrux-chacha20poly1305`, `libcrux-curve25519`, `libcrux-ecdsa`,
  `libcrux-hacl-rs`, `libcrux-intrinsics`, `libcrux-macros`,
  `libcrux-ml-kem`, `libcrux-p256`, `libcrux-poly1305`, `libcrux-secrets`,
  `libcrux-sha2`, `libcrux-sha3`, `libcrux-traits`.
- **`rand`, `rand_core`, `syn`, `quote`, `proc-macro2`, `unicode-ident`**,
  stored unmodified with their license files. `rand` and `rand_core` supply
  trait definitions; the others run only at build time.
- **Every other directory in `vendor/`** is a stub of a crate that
  `Cargo.lock` lists but that is never compiled: its upstream `Cargo.toml`
  and an empty source file, no code.

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
