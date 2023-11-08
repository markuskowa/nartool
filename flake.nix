{
  inputs.nixpkgs.url = "github:nixos/nixpkgs";

  description = "NAR tool";

  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.nartool = let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      inherit (pkgs.python3.pkgs)
        buildPythonApplication
        setuptools
        requests;
    in
      buildPythonApplication {
        pname = "nartool";
        version = "0.0.1";

        format = "pyproject";

        src = ./.;

        nativeBuildInputs =  [ setuptools ];
        propagatedBuildInputs = [ requests ];
      };
  };
}
