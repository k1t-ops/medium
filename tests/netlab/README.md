# Medium Netlab

Podman-based end-to-end tests that model a realistic Medium deployment with
isolated networks:

- `control-relay`: control-plane and TCP relay on a public subnet.
- `office-node`: node-agent, OpenSSH server, and an HTTP fixture behind an
  office NAT.
- `p2p-client`: Medium CLI and OpenSSH client on the office LAN, used for
  deterministic direct ICE UDP checks.
- `relay-client`: Medium CLI and OpenSSH client behind a separate client NAT,
  used for forced relay checks.
- `office-gw` and `client-gw`: gateway containers with IPv4 forwarding and
  nftables masquerade.

Run:

```sh
just netlab-relay-ssh
```

The test builds a Linux runtime image, initializes Medium using the production
CLI bootstrap commands, joins clients, waits for the service catalog, then runs
the scenario matrix:

- `medium ssh -v studio-smiley` from `p2p-client`, expecting `ice_udp/*`.
- `medium ssh -v --relay studio-smiley` from `relay-client`, expecting
  `relay_tcp`.
- Raw HTTP `GET /` through `medium proxy service --node studio-smiley --service
  hello -v` from `p2p-client`, expecting `ice_udp/*`.
- The same raw HTTP request with `--relay` from `relay-client`, expecting
  `relay_tcp`.

The SSH scenarios also authenticate to OpenSSH with a Medium-issued ephemeral
SSH certificate. The HTTP scenarios complete Medium service TLS for
`hello.medium` and verify the fixture response.

Logs and transient state are written under `.medium-local/netlab`.
