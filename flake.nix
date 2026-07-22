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
        flask waitress requests duckdb pyjwt cryptography python-dateutil pytz markdown python-magic
      ]);

      # Package the whole forms/ subtree — the .py plus templates/ — into
      # a single store path so Flask's template_folder can find them at
      # runtime. Passing just the .py as entrypoint would strand the
      # templates outside the store.
      formsSrc = pkgs: pkgs.runCommandLocal "gluck-forms-src" { } ''
        mkdir -p $out
        cp ${./forms/gluck_forms.py} $out/gluck_forms.py
        mkdir -p $out/templates
        cp ${./forms/templates}/*.html $out/templates/
      '';

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
              entrypoint = "${formsSrc pkgs}/gluck_forms.py";
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
                python-magic
              ];
              stateDirectory = "gluck-forms";
              environment = {
                GLUCK_FORMS_DB = "/var/lib/gluck-forms/forms.duckdb";
                GLUCK_FORMS_MATERIALS_DIR = "/var/lib/gluck-forms-blobs/materials";
                GLUCK_FORMS_RESPONSES_DIR = "/var/lib/gluck-forms-blobs/responses";
              };
              # Two ZFS-backed volumes provided by the platform storage
              # contract; wait for both to mount before start.
              after = [
                "kelliher-web-volume-gluck-forms-data.service"
                "kelliher-web-volume-gluck-forms-blobs.service"
                "network.target"
              ];
              # Retire DynamicUser: the platform's storage ensurer chowns
              # the mount points to a named user, and DynamicUser's UID
              # shifts break that. Static system user instead.
              extraServiceConfig = {
                DynamicUser = false;
                User = "gluck-forms";
                Group = "gluck-forms";
                StateDirectory = [ ];
                RequiresMountsFor = [
                  "/var/lib/gluck-forms"
                  "/var/lib/gluck-forms-blobs"
                ];
                # ProtectSystem=strict (inherited from gluck-service-lib)
                # makes /var and everything under it read-only for the
                # process unless we explicitly grant write access to the
                # volumes we own.
                ReadWritePaths = [
                  "/var/lib/gluck-forms"
                  "/var/lib/gluck-forms-blobs"
                ];
              };
              requireAuth = true;
              requiredGroups = [ "forms-admin" ];
            })

            {
              # Static system user matching the platform's chown target.
              users.users.gluck-forms = {
                isSystemUser = true;
                group = "gluck-forms";
              };
              users.groups.gluck-forms = { };

              # Platform storage: one dataset for the DB (small, tuned for
              # duckdb pages, critical snapshots), one for blobs (larger,
              # 128K records, standard app snapshots).
              services.kelliher-web.storage.volumes.gluck-forms-data = {
                mountPoint = "/var/lib/gluck-forms";
                owner = "gluck-forms";
                quota = "5G";
                recordsize = "16K";
                snapshotProfile = "critical";
              };
              services.kelliher-web.storage.volumes.gluck-forms-blobs = {
                mountPoint = "/var/lib/gluck-forms-blobs";
                owner = "gluck-forms";
                quota = "50G";
                recordsize = "128K";
                snapshotProfile = "app";
              };

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
            export GLUCK_FORMS_MATERIALS_DIR=$PWD/.local-blobs/materials
            export GLUCK_FORMS_RESPONSES_DIR=$PWD/.local-blobs/responses
            export PORT=9095
          '';
        };
      });

      packages = forAllSystems (pkgs: {
        default = pyEnv pkgs;
        src = formsSrc pkgs;
      });
    };
}
