# Harbour development shell
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "harbour-dev";
  buildInputs = [ pkgs.rustc pkgs.cargo ];
  /* environment */
  RUST_LOG = "info";
}
