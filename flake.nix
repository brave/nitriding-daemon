{
  description = "Nitriding daemon";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-24.05";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs { inherit system; };

    in {
      packages.x86_64-linux.default = pkgs.buildGoModule {
        pname = "nitriding-daemon";
        version = "1.4.2";
        src = builtins.filterSource
          (path: type:
            let relPath = pkgs.lib.removePrefix (toString ./. + "/") path;
            in pkgs.lib.hasSuffix ".go" relPath ||
                pkgs.lib.hasSuffix ".mod" relPath ||
                pkgs.lib.hasSuffix ".sum" relPath)
          ./.;
        vendorHash = "sha256-KKgDI8W2Xbpfr3lRuSYH4fdOjPFfQZdapg7m09pXm80=";
        CGO_ENABLED = 0;
        ldflags = ["-s" "-w"];
        checkFlags = ["-skip"];
    };
  };
}
