{ nixpkgs ? <nixpkgs> }:

let
  pkgs = import <nixpkgs> {};

  inherit (pkgs.python3.pkgs) buildPythonApplication requests setuptools;

in buildPythonApplication {
  pname = "nartool";
  version = "0.0.1";

  format = "pyproject";

  src = ./.;

  nativeBuildInputs =  [ setuptools ];
  propagtedBuildInputs = [ requests ];
}

