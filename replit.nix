{pkgs}: {
  deps = [
    pkgs.iana-etc
    pkgs.rustc
    pkgs.pkg-config
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.gmp
    pkgs.postgresql
    pkgs.openssl
  ];
}
