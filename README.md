# Medium

Medium is a personal service-access overlay for reaching your own machines from anywhere.

The first practical target is simple: run a control plane, run a node agent on a
machine that hosts your services, join a client machine, then use regular SSH:

```sh
ssh node-1
```

Medium is currently an early MVP. The implemented path focuses on a control
plane, a headless node agent, SQLite-backed registry state, direct TCP sessions
to published nodes with TCP relay fallback, and generated SSH config.

## Install

From the GitHub project. The installer downloads prebuilt release binaries; it
does not require Rust or Cargo on the target machine:

```sh
curl -fsSL https://raw.githubusercontent.com/burniq/medium/main/scripts/install.sh | sh
```

For a fork or private repo:

```sh
curl -fsSL https://raw.githubusercontent.com/burniq/medium/main/scripts/install.sh | MEDIUM_REPO=burniq/medium sh
```

The installer downloads `medium-${MEDIUM_VERSION:-0.0.4}-${target}.tar.gz` from
GitHub Releases. If `medium` is already in `PATH`, the installer updates that
existing location. Otherwise it installs into `/usr/bin` on Linux and
`/usr/local/bin` on macOS by default:

- `medium`
- `control-plane`
- `node-agent`
- `relay`

Use a specific release or target when needed:

```sh
curl -fsSL https://raw.githubusercontent.com/burniq/medium/main/scripts/install.sh | \
  MEDIUM_VERSION=0.0.4 MEDIUM_TARGET=linux-x86_64 sh
```

Use a different install prefix if needed:

```sh
curl -fsSL https://raw.githubusercontent.com/burniq/medium/main/scripts/install.sh | PREFIX="$HOME/.local" sh
```

Source builds are an explicit fallback for development machines:

```sh
curl -fsSL https://raw.githubusercontent.com/burniq/medium/main/scripts/install.sh | MEDIUM_INSTALL_FROM_SOURCE=1 sh
```

Release archives are published automatically by GitHub Actions when a tag like
`v0.0.4` is pushed. The release workflow uploads:

- `medium-<version>-linux-x86_64.tar.gz`
- `medium-<version>-linux-aarch64.tar.gz`
- `medium-<version>-darwin-arm64.tar.gz`
- `medium-<version>-darwin-x86_64.tar.gz`

## Control Plane

Run this on the machine that will act as the discovery/control-plane node. This
can be a VPS, a home server, or any host reachable by the nodes that need to
join the network:

```sh
sudo medium init-control
```

`medium init-control` creates the control-plane config under `/etc/medium`,
generates a pinned self-signed control-plane TLS identity, creates state under
`/var/lib/medium`, renders the `medium-control-plane` and `medium-relay`
systemd units, and prints two invites:

- `medium://join?...` for client machines.
- `medium://node?...` for server nodes. Treat this invite as sensitive because
  the current MVP includes the node session secret in it.

By default the control plane listens on `0.0.0.0:7777` and derives its public
URL from the machine's primary non-loopback IP. Override it when you need a
stable DNS name, a specific IP, or a different port:

```sh
sudo MEDIUM_CONTROL_PUBLIC_URL="https://control.example.com:8443" \
  MEDIUM_CONTROL_BIND_ADDR="0.0.0.0:8443" \
  medium init-control
```

The relay listens on `0.0.0.0:7001` by default and is advertised to joined
nodes through the generated node invite. Override it when the relay uses a
different externally reachable address:

```sh
sudo MEDIUM_RELAY_PUBLIC_ADDR="relay.example.com:7001" medium init-control
```

After bootstrap, check status:

```sh
medium doctor
```

To inspect which nodes and services are registered on the control-plane host,
use the server-side registry diagnostic command:

```sh
sudo medium control devices
```

`medium devices` is a client command and requires `medium join`. On a
control-plane host, use `medium control devices` to read the control-plane
registry directly.

## Publishing Services

Medium exposes machines through `node-agent`. Run this on a service node: any
machine that hosts SSH, web apps, HTTP APIs, or other TCP services:

```sh
sudo MEDIUM_NODE_ID="workstation-1" \
  medium init-node 'medium://node?v=1&control=https://control.example.com:7777&security=pinned-tls&control_pin=sha256:...&shared_secret=...'
```

By default the node agent listens on `0.0.0.0:17001` and derives its public
address from the machine's primary non-loopback IP. Override it when clients
must use a DNS name, a specific IP, or a forwarded NAT address:

```sh
sudo MEDIUM_NODE_ID="workstation-1" \
  MEDIUM_NODE_PUBLIC_ADDR="workstation-1.example.com:17001" \
  medium init-node 'medium://node?v=1&control=https://control.example.com:7777&security=pinned-tls&control_pin=sha256:...&shared_secret=...'
```

Clients try the node's direct TCP candidate first. If that path is unreachable,
they fall back to the relay advertised by the control plane. This lets a node
behind NAT keep outbound relay connections without opening an inbound port.

On Linux, `medium init-node` creates `~/.medium/node.toml` and
`~/.medium/services.toml` with a default SSH service. When run with `sudo`, the
configs are written under the target user's home, for example
`/root/.medium/node.toml`. Linux installs also enable `medium-node-agent.service`.

On macOS, `medium init-node` creates the same files under `~/.medium`. Run the
node agent from a terminal:

```sh
medium run
```

The generated node config contains node identity, control-plane, and transport
settings:

```toml
node_id = "workstation-1"
node_label = "workstation-1"
bind_addr = "0.0.0.0:17001"
public_addr = "192.0.2.10:17001"
control_url = "https://control.example.com:7777"
control_pin = "sha256:..."
shared_secret = "medium-shared-secret-..."
```

The generated service catalog lives in `~/.medium/services.toml`:

```toml
[[services]]
id = "svc_ssh"
kind = "ssh"
target = "127.0.0.1:22"
user_name = "overlay"
enabled = true
```

You can add more published services to `~/.medium/services.toml`:

```toml
[[services]]
id = "svc_web"
kind = "http"
target = "127.0.0.1:3000"
enabled = true
```

After changing `services.toml`, restart the agent:

```sh
sudo systemctl restart medium-node-agent
```

Joined clients can discover published SSH services with `medium devices` and
connect with `medium ssh <node>`. Medium generates a fresh ephemeral SSH key for
each connection, asks the control plane for a short-lived OpenSSH certificate,
and then opens the SSH session through Medium transport. The control plane is
used for discovery and session initialization. SSH traffic uses the same Medium
session transport as published web services: ICE UDP is tried first, legacy
direct/relay candidates are used as fallback, and the SSH byte stream is
wrapped in Medium service TLS before it reaches the node. Use
`medium ssh --relay <node>` to skip direct candidates and force relay transport
for diagnostics or constrained networks.

### Test Published Service

To publish a local test service from any service node, start a dummy HTTP
server:

```sh
mkdir -p /tmp/medium-dummy
printf 'hello from medium\n' >/tmp/medium-dummy/index.html
python3 -m http.server 3000 --directory /tmp/medium-dummy --bind 127.0.0.1
```

Then add it to `~/.medium/services.toml`:

```toml
[[services]]
id = "svc_dummy_web"
kind = "http"
label = "Dummy Web"
target = "127.0.0.1:3000"
enabled = true
```

Restart the node agent:

```sh
sudo systemctl restart medium-node-agent
medium doctor
```

Clients can then discover the service catalog and open a Medium session for the
published service.

## Client Join

Run this on a client machine:

```sh
medium join 'medium://join?v=1&control=https://control.example.com:7777&security=pinned-tls&control_pin=sha256:...'
medium devices
medium services
medium ssh workstation-1
medium ssh --relay workstation-1
```

`medium ssh <node>` is the primary SSH entrypoint. It does not require copying
client keys into `authorized_keys`.

## iOS App

The iOS app is currently installed from source with Xcode. Automatic TestFlight
or App Store distribution is not wired yet.

Prerequisites:

- macOS with Xcode.
- An Apple Developer team selected in Xcode for device signing.
- Optional: `xcodegen` if you want to regenerate the project from
  `apps/apple/project.yml`.

Open the project:

```sh
cd apps/apple
xcodegen generate
open MediumApple.xcodeproj
```

In Xcode:

- Select the `MediumApp` scheme.
- Select your connected iPhone as the run destination.
- Set your signing team for the `MediumApp` target if Xcode asks.
- Run the app.

Create a client invite on the control-plane host. If you no longer have the
`medium init-control` output, reconstruct the join invite from
`/etc/medium/control.toml`:

```sh
sudo sh -c '
control=$(awk -F\" "/^control_url = / {print \$2}" /etc/medium/control.toml)
pin=$(awk -F\" "/^control_pin = / {print \$2}" /etc/medium/control.toml)
printf "medium://join?v=1&control=%s&security=pinned-tls&control_pin=%s\n" "$control" "$pin"
'
```

Paste that `medium://join?...` invite into the iOS app. After joining, tap
`Refresh` to load published nodes and services. Tapping a service opens a
Medium session and shows direct/relay candidates.

## Android App

The Android app can be built locally without a paid platform subscription. It
uses Android's system routing service, so the first tunnel start shows a
standard Android network permission prompt.

Build and install a debug APK:

```sh
cd apps/android
gradle installDebug
```

Create a client invite on the control-plane host. If you no longer have the
`medium init-control` output, reconstruct the join invite from
`/etc/medium/control.toml`:

```sh
sudo sh -c '
control=$(awk -F\" "/^control_url = / {print \$2}" /etc/medium/control.toml)
pin=$(awk -F\" "/^control_pin = / {print \$2}" /etc/medium/control.toml)
printf "medium://join?v=1&control=%s&security=pinned-tls&control_pin=%s\n" "$control" "$pin"
'
```

Paste that `medium://join?...` invite into the Android app, tap `Refresh` to
load published services, then tap `Start` in the tunnel section to authorize
and start Medium routing.

## Development

Common local commands:

```sh
just rust-test
just e2e-init-control-join
just e2e-package
just package
```

The packaged Linux layout is documented in `packaging/linux/README.md`.

## License

Medium is licensed under the MIT License. See `LICENSE` for details.
