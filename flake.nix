{
  description = "shioko development tools (nothing here ends up in the binary)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in {
      # Rust itself comes from rustup, pinned by rust-toolchain.toml.
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.tlaplus # TLC model checker
            pkgs.openssl # TLS interop client
            pkgs.curl
          ];
        };
      });
    };
}
