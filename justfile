set shell := ["bash", "-cu"]

rust-test:
  cargo test --workspace

rust-test-cached:
  source scripts/cache-env.sh && cargo test --workspace

android-test:
  cd apps/android && gradle test

disk-usage:
  bash scripts/disk-usage.sh

smoke:
  bash tests/e2e/smoke.sh

package:
  bash scripts/package.sh

e2e-package:
  bash tests/e2e/package_layout.sh

e2e-install:
  bash tests/e2e/install_script.sh

e2e-release-workflow:
  test -f .github/workflows/release.yml
  grep -Fq 'actions/checkout@v6' .github/workflows/release.yml
  grep -Fq 'actions/upload-artifact@v7' .github/workflows/release.yml
  grep -Fq 'actions/download-artifact@v7' .github/workflows/release.yml
  grep -Fq 'runner: ubuntu-24.04' .github/workflows/release.yml
  grep -Fq 'runner: ubuntu-24.04-arm' .github/workflows/release.yml
  grep -Fq 'runner: macos-15' .github/workflows/release.yml
  grep -Fq 'runner: macos-15-intel' .github/workflows/release.yml
  grep -Fq 'linux-x86_64' .github/workflows/release.yml
  grep -Fq 'linux-aarch64' .github/workflows/release.yml
  grep -Fq 'darwin-arm64' .github/workflows/release.yml
  grep -Fq 'darwin-x86_64' .github/workflows/release.yml
  grep -Fq 'needs: package' .github/workflows/release.yml
  grep -Fq 'softprops/action-gh-release@v3' .github/workflows/release.yml

e2e-init-control-join:
  bash tests/e2e/init_control_join.sh

e2e-wss-relay:
  bash tests/e2e/wss_relay.sh

netlab-relay-ssh:
  bash tests/netlab/run.sh
