{ pkgs ? import <nixpkgs> { } }: with pkgs;

let
    libs = [
        (lib.getLib gcc13Stdenv.cc.cc)
        libmpc
        mpfr
        gmp
        zlib
        zstd
        ncurses
        libxcrypt
        openssl
    ];
in
mkShell.override { stdenv = gcc13Stdenv; } {
  packages = [
    ccache
    cmake
    curl
    e2fsprogs
    fuse2fs
    gcc13
    mold-wrapped
    lld
    # To create port launcher icons
    imagemagick
    ninja
    patch
    pkg-config
    rsync
    texinfo
    unzip
    # To build the GRUB disk image
    grub2
    parted
    qemu
    python3
  ] ++ libs;
  LD_LIBRARY_PATH = lib.makeLibraryPath libs;
  hardeningDisable = [ "format" ];
}
