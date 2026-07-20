{
  description = "gluck-forms — generic forms service behind kelliher-web (admin API + public form filler)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    gluck-service-lib.url = "github:jack-work/gluck-service-lib";
    gluck-service-lib.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, gluck-service-lib, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      pyEnv = pkgs: pkgs.python3.withPackages (ps: with ps; [
        flask waitress requests duckdb pyjwt cryptography python-dateutil pytz markdown
      ]);

      nixosModule =
        { config, lib, pkgs, ... }:
        let
          cfg = config.services.gluck-forms;
        in
        {
          options.services.gluck-forms = {
            enable = lib.mkEnableOption "gluck-forms (admin API on forms.<base>, public filler on f.<base>)";

            port = lib.mkOption {
              type = lib.types.port;
              default = 9095;
              description = "Loopback port for the forms backend. Both sites proxy here; the app routes by Host header.";
            };
          };

          # Two Caddy sites, one backend. `mkPythonService` gives us the
          # systemd unit + the admin site; we then add the public site
          # (requireAuth = false) alongside it.
          config = lib.mkIf cfg.enable (lib.mkMerge [
            (gluck-service-lib.lib.mkPythonService {
              inherit config lib pkgs;
              name = "gluck-forms";
              subdomain = "forms";
              port = cfg.port;
              entrypoint = ./forms/gluck_forms.py;
              pythonPackages = ps: with ps; [
                flask
                waitress
                requests
                duckdb
                pyjwt
                cryptography
                python-dateutil
                pytz
                markdown
              ];
              stateDirectory = "gluck-forms";
              environment = {
                GLUCK_FORMS_DB = "/var/lib/gluck-forms/forms.duckdb";
                GLUCK_FORMS_BLOBS = "/var/lib/gluck-forms/blobs";
              };
              requireAuth = true;
              requiredGroups = [ "gluck-forms-admin" ];
            })

            {
              # Public form-filler site: no Authelia, no group. The URL
              # token IS the capability; the app validates it.
              services.kelliher-web.sites.gluck-forms-public = {
                subdomains = [ "f" ];
                requireAuth = false;
                requiredGroups = [ ];
                proxyTo = cfg.port;
              };
            }
          ]);
        };
    in
    {
      nixosModules.default = nixosModule;

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [ (pyEnv pkgs) ];
          shellHook = ''
            export GLUCK_FORMS_DB=$PWD/.local.duckdb
            export GLUCK_FORMS_BLOBS=$PWD/.local-blobs
            export PORT=9095
          '';
        };
      });

      packages = forAllSystems (pkgs: {
        default = pyEnv pkgs;
      });
    };
}
