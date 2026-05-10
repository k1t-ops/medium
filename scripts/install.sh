#!/usr/bin/env sh
set -eu

repo="${MEDIUM_REPO:-burniq/medium}"
version="${MEDIUM_VERSION:-0.0.4}"
release_tag="${MEDIUM_RELEASE_TAG:-v$version}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "medium installer: missing required command: $1" >&2
    exit 1
  fi
}

need curl
need id
need install
need mkdir
need mktemp
need rm
need tar
need uname

install_privilege() {
  bin_dir="$1/bin"
  if [ "$(id -u)" -eq 0 ]; then
    mkdir -p "$bin_dir"
    echo ""
    return
  fi

  if mkdir -p "$bin_dir" 2>/dev/null; then
    probe="$bin_dir/.medium-install-write-test.$$"
    if ( : >"$probe" ) 2>/dev/null; then
      rm -f "$probe"
      echo ""
      return
    fi
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    echo "medium installer: $bin_dir is not writable and sudo is not available" >&2
    exit 1
  fi

  sudo mkdir -p "$bin_dir"
  echo "sudo"
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64) echo "linux-x86_64" ;;
    Linux:aarch64|Linux:arm64) echo "linux-aarch64" ;;
    Darwin:arm64) echo "darwin-arm64" ;;
    Darwin:x86_64) echo "darwin-x86_64" ;;
    *)
      echo "medium installer: unsupported target $os/$arch" >&2
      echo "medium installer: set MEDIUM_TARGET to override" >&2
      exit 1
      ;;
  esac
}

target="${MEDIUM_TARGET:-$(detect_target)}"
case "$target" in
  linux-*) default_prefix="/usr" ;;
  darwin-*) default_prefix="/usr/local" ;;
  *) default_prefix="/usr/local" ;;
esac
install_prefix() {
  if [ -n "${PREFIX:-}" ]; then
    echo "$PREFIX"
    return
  fi

  if command -v medium >/dev/null 2>&1; then
    existing_medium="$(command -v medium)"
    existing_dir="${existing_medium%/*}"
    case "$existing_dir" in
      */bin)
        existing_prefix="${existing_dir%/bin}"
        if [ -z "$existing_prefix" ]; then
          existing_prefix="/"
        fi
        echo "$existing_prefix"
        return
        ;;
    esac
  fi

  echo "$default_prefix"
}

prefix="$(install_prefix)"
if [ -z "${PREFIX:-}" ] && command -v medium >/dev/null 2>&1; then
  echo "medium installer: updating existing $(command -v medium)"
fi

if [ "${MEDIUM_INSTALL_FROM_SOURCE:-}" = "1" ]; then
  need cargo
  need find
  need sed
  ref="${MEDIUM_REF:-main}"

  workdir="$(mktemp -d "${TMPDIR:-/tmp}/medium-install.XXXXXX")"
  cleanup() {
    rm -rf "$workdir"
  }
  trap cleanup EXIT INT TERM

  archive="$workdir/source.tar.gz"
  url="https://github.com/$repo/archive/$ref.tar.gz"

  echo "medium installer: downloading $url"
  curl -fsSL "$url" -o "$archive"
  tar -xzf "$archive" -C "$workdir"

  src_dir="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d | sed -n '1p')"
  if [ -z "$src_dir" ]; then
    echo "medium installer: failed to locate unpacked source directory" >&2
    exit 1
  fi

  cargo_target_dir="${CARGO_TARGET_DIR:-$src_dir/target}"
  case "$cargo_target_dir" in
    /*) ;;
    *) cargo_target_dir="$src_dir/$cargo_target_dir" ;;
  esac

  echo "medium installer: building release binaries"
  (
    cd "$src_dir"
    cargo build --release -p control-plane -p home-node -p medium-cli -p relay
  )

  sudo_cmd="$(install_privilege "$prefix")"

  echo "medium installer: installing into $prefix/bin"
  for bin in medium control-plane relay; do
    $sudo_cmd install -m 0755 "$cargo_target_dir/release/$bin" "$prefix/bin/$bin"
  done
  $sudo_cmd install -m 0755 "$cargo_target_dir/release/home-node" "$prefix/bin/node-agent"

  echo "medium installer: installed medium"
  echo "next server step: sudo medium init-control"
  exit 0
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/medium-install.XXXXXX")"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

archive="$workdir/medium.tar.gz"
asset="medium-$version-$target.tar.gz"
release_base_url="${MEDIUM_RELEASE_BASE_URL:-https://github.com/$repo/releases/download/$release_tag}"
url="$release_base_url/$asset"

echo "medium installer: downloading $url"
curl -fsSL "$url" -o "$archive"
tar -xzf "$archive" -C "$workdir"
package_dir="$workdir"

sudo_cmd="$(install_privilege "$prefix")"

echo "medium installer: installing into $prefix/bin"
for bin in medium control-plane relay; do
  $sudo_cmd install -m 0755 "$package_dir/bin/$bin" "$prefix/bin/$bin"
done
$sudo_cmd install -m 0755 "$package_dir/bin/node-agent" "$prefix/bin/node-agent"

echo "medium installer: installed medium"
echo "next server step: sudo medium init-control"
