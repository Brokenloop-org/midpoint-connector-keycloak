{
  description = "connector-keycloak development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        kcPath = pkgs.lib.makeBinPath [
          pkgs.coreutils pkgs.gnused pkgs.gnugrep pkgs.findutils
          pkgs.gawk pkgs.which pkgs.curl pkgs.jdk17
        ];

        startKeycloak = pkgs.writeShellScript "start-keycloak" ''
          set -euo pipefail
          export PATH="${kcPath}:$PATH"
          export JAVA_HOME="${pkgs.jdk17}"

          # Create a writable KC home (Quarkus start-dev writes to lib/ and conf/)
          KC_WORK="$(mktemp -d)"
          cp -r ${pkgs.keycloak}/{lib,conf,providers,themes,version.txt} "$KC_WORK/"
          chmod -R u+w "$KC_WORK"
          mkdir -p "$KC_WORK/data"

          export KC_HOME_DIR="$KC_WORK"
          export KC_CONF_DIR="$KC_WORK/conf"
          export KC_BOOTSTRAP_ADMIN_USERNAME=admin
          export KC_BOOTSTRAP_ADMIN_PASSWORD=admin

          echo "Starting Keycloak (KC_HOME_DIR=$KC_WORK)..."
          ${pkgs.keycloak}/bin/kc.sh start --http-enabled=true --hostname-strict=false --http-port=8090 --features=organization &
          KC_PID=$!
          echo "$KC_PID" > "$KC_WORK/kc.pid"
          echo "$KC_WORK" > /tmp/kc-integration-test-home

          echo "Waiting for Keycloak to be ready..."
          for i in $(seq 1 120); do
            if curl -sf http://localhost:8090/realms/master > /dev/null 2>&1; then
              echo "Keycloak ready after ''${i}s (PID $KC_PID)"
              exit 0
            fi
            sleep 1
          done
          echo "Keycloak failed to start within 120s"
          kill $KC_PID 2>/dev/null || true
          exit 1
        '';

        stopKeycloak = pkgs.writeShellScript "stop-keycloak" ''
          export PATH="${pkgs.lib.makeBinPath [ pkgs.coreutils ]}:$PATH"
          if [ -f /tmp/kc-integration-test-home ]; then
            KC_HOME_DIR=$(cat /tmp/kc-integration-test-home)
            if [ -f "$KC_HOME_DIR/kc.pid" ]; then
              KC_PID=$(cat "$KC_HOME_DIR/kc.pid")
              echo "Stopping Keycloak (PID $KC_PID)..."
              kill $KC_PID 2>/dev/null || true
              wait $KC_PID 2>/dev/null || true
            fi
            rm -rf "$KC_HOME_DIR"
            rm -f /tmp/kc-integration-test-home
          fi
        '';
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.jdk17
            pkgs.maven
            pkgs.keycloak
          ];

          shellHook = ''
            export JAVA_HOME="${pkgs.jdk17}"
            echo "connector-keycloak dev shell"
            echo "  Java:     $(java -version 2>&1 | head -1)"
            echo "  Maven:    $(mvn -version 2>&1 | head -1)"
            echo "  Keycloak: ${pkgs.keycloak.version}"
            echo ""
            echo "Commands:"
            echo "  nix run .#start-keycloak   # Start Keycloak on :8090"
            echo "  mvn test                   # Run unit tests"
            echo "  mvn verify -Dgpg.skip      # Run unit + integration tests"
            echo "  nix run .#stop-keycloak    # Stop Keycloak"
            echo "  nix run .#integration-test # All-in-one: start KC, test, stop"
          '';
        };

        apps.start-keycloak = {
          type = "app";
          program = toString startKeycloak;
        };

        apps.stop-keycloak = {
          type = "app";
          program = toString stopKeycloak;
        };

        apps.integration-test = {
          type = "app";
          program = toString (pkgs.writeShellScript "integration-test" ''
            set -euo pipefail
            export PATH="${pkgs.lib.makeBinPath [ pkgs.jdk17 pkgs.maven pkgs.curl pkgs.coreutils ]}:${kcPath}"
            export JAVA_HOME="${pkgs.jdk17}"

            # Start Keycloak
            ${startKeycloak}

            # Run tests
            echo "Running tests..."
            mvn verify -Dgpg.skip=true -Dmaven.javadoc.skip=true -Dmaven.source.skip=true || EXIT=$?

            # Stop Keycloak
            ${stopKeycloak}

            exit ''${EXIT:-0}
          '');
        };
      });
}
