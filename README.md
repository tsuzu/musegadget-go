# musegadget-go

An unofficial Go reimplementation of the Muse Gadgets client protocol,
protocol-compatible with the Linux Device SDK in
[facebookincubator/muse-gadget-sdk](https://github.com/facebookincubator/muse-gadget-sdk).

It implements pairing v5 over BLE, the Muse API, Noise XX sessions with
the reference's protobuf-style framing, the link protocol, and the device
command executor — plus an Android facade (`mobile/`) for embedding in an
Android app (for example, on a modified Echo Show or another always-on
Android device).

> **Note on the upstream `android/` directory:** In the upstream
> repository, `android/` is *not* a gadget client SDK. It is
> "Muse Gadgets Test", a sample phone app that streams camera video to a
> gadget display over Wi-Fi (see its `protocols/VIDEO.md`). The VIDEO
> protocol is out of scope here. The Android client entry point in this
> repository is the `mobile/` package described below.

## Status

- Pairing v5 test vectors from the upstream SDK **pass** (see
  *Verification* below).
- Noise handshake / framing / envelope bytes match golden bytes generated
  from the upstream Python implementation.
- Self-consistency end-to-end tests pass against a fake VM (real
  WebSocket + Noise responder): register, chat, invoke, subscribe, and
  unpaired handling.
- **No real Muse account connection has been attempted.** Verification
  stops at test vectors, golden bytes, and fake-VM tests.
- **The BLE GATT server transport is not implemented** (see *Limitations*).

## Requirements

- Go 1.23 or later

## Build

```sh
go build ./...
go build -o musegadget ./cmd/musegadget
```

Cross-check for Android (the `mobile/` package follows gomobile's rules):

```sh
GOOS=android GOARCH=arm64 go build ./...
```

## Test

```sh
go vet ./...
go test ./...
go test -race ./...
```

## CLI usage

The `musegadget` command mirrors the reference CLI (except `voice-call`
and `doctor`, which are out of scope for the minimal client).

```sh
# Show identity and pairing state
musegadget info

# Pair with the Muse app (requires a working BLE ServerFactory backend;
# the default factory returns ErrUnavailable — see Limitations)
musegadget pair [--timeout <seconds>] [--force]

# Run the service: reconnect supervisor, link session, command executor
musegadget run [--run-as ACCOUNT]   # --run-as is required when running as root

# Send a message to Muse via the running service's local socket
musegadget send-user-msg [--session-id ID] [--image FILE] <message...>
musegadget send-user-msg -          # read the message from stdin

# Remove local pairing state
musegadget unpair
```

You need an SDK token (`mgst_…`) from
[gadgets.muse.ai/settings/sdk-tokens](https://gadgets.muse.ai/settings/sdk-tokens)
and Developer Mode enabled in the Muse app (Settings > Devices) to pair
a real device. State (identity, pairing material) is stored as JSON files
with 0600 permissions in the state directory; never commit that directory.

## Layout

| Package | Upstream reference | Contents |
| --- | --- | --- |
| `wirejson` | — | JSON with Python `json.dumps` byte semantics (escaping, float formatting, key order), which the wire formats depend on |
| `config` | `config.py` | State directory / environment variables, atomic 0600 JSON state files, SDK token (`mgst_…`) validation |
| `identity` | `identity.py` | Persistent identity MAC, `homelink-xxxxxx` node id, `MuseGadgetXXXXXX` BLE name |
| `pairing` | `pairing.py` | Pairing v5: P-256 ECDH + HKDF-SHA256 + AES-256-GCM, `confirm_app` policy |
| `ble` | `ble_framing.py`, `ble_setup.py`, `ble_server.py` | `0xFE` chunk framing, transport-independent setup controller, GATT UUIDs, `Server` / `ServerFactory` platform interface |
| `museapi` | `muse_api.py` | `fetch_vms`, device-token refresh against `https://api.muse.ai` (or `api_url_v2` from provisioning) |
| `noise` | `noise/` | `Noise_XX_25519_AESGCM_SHA256`, hand-rolled (the reference's AES-GCM nonce is big-endian, unlike standard Noise libraries), protobuf-style framing / envelope |
| `streaming` | `streaming.py` | HTTP stream multiplexing over a Noise session, NDJSON reader |
| `linkclient` | `link_client.py` | `wss://<host>/v1/noise?vm_id=` transport, `/link-control` register / invoke, `/chat/stream` send chat / voice / image, subscribe, TTS |
| `executor` | `executor.py`, `commands.py`, `fileops.py` | `device.health`, `system.run`, `file.read`, `file.write`, `commands.d` drop-ins |
| `service` | `service.py`, `pair.py`, `network.py` | Reconnect supervisor with backoff and token rotation, local message socket, pair orchestration, online check |
| `mobile` | — (Android) | gomobile-friendly facade: identity, `Pair` via an injected BLE bridge, `Start` / `Stop`, `SendUserMessage` |
| `cmd/musegadget` | `cli.py` | `pair`, `run`, `send-user-msg`, `info`, `unpair` |

### Link registration notes

The link client registers with `platform: "linux"` and
`device_family: "homehub"`. It intentionally never uses family `link`
and never advertises `device.ota`: the server pushes ESP32 firmware
updates to `link` devices.

## Limitations

Honest list of what is stubbed, unverified, or different:

- **BLE GATT server:** Behind `ble.ServerFactory`. No platform backend
  ships in this build — the default factory returns
  `ble.ErrUnavailable`. On Linux, the reference drives BlueZ over D-Bus
  (not ported). On Android, the host app is expected to inject a factory
  backed by `BluetoothGattServer` through the `mobile` package's
  `BLEBridge`. All pairing cryptography, framing, and setup-command
  handling *above* the transport is implemented and tested.
- **gomobile `.aar`:** The `mobile/` package is written to gomobile's
  rules (only strings / bytes / primitives cross the boundary) and builds
  normally, including for `GOOS=android`. Producing an `.aar` with
  gomobile itself is **unverified** in the author's environment.
- **fileops execution model:** File operations run in-process. The
  reference runs them in a child process as the command account.
  `system.run` and drop-in commands do run as the account (credentials
  are applied when the service runs as root).
- **Network SSID lookup:** Only the `nmcli` path is ported; the
  `wpa_cli` path is not, and a fallback string is shown instead.
- **User-Agent:** The trailing component differs from the Python
  reference (`Go/<version>` instead of the Python runtime string). The
  overall format follows the reference.
- **device.health load average:** Read from `/proc/loadavg` (the
  reference uses `os.getloadavg()`); rounding matches Python's banker's
  rounding.

## Verification

No real Muse account was contacted during development. Verification
consists of:

- The upstream pairing test vectors
  (`pairing/testdata/link_pairing_v5.json` — factual test data from the
  upstream SDK): transcript, key schedule, `pairing_ready`,
  `client_finished` decryption, replay rejection, and expiry all pass.
- Golden bytes generated from the upstream Python implementation for the
  Noise handshake, transport framing, and service envelope.
- Self-consistency tests: Go-to-Go Noise handshake, a fake VM performing
  a real Noise handshake over a real WebSocket, and a service-level
  integration test (pairing state → `fetch_vms` → registration → a chat
  message delivered to the VM over the local socket → clean shutdown).
- `go build ./...`, `go vet ./...`, and `go test ./...` (including
  `-race`) all pass.

## Important notices

- This is an **unofficial** reimplementation. It is not affiliated with
  or endorsed by Meta.
- Per the upstream SDK's own terms, Muse Gadgets is **not a supported
  developer platform**: the SDK, tokens, and protocol can change or stop
  working without notice. Do not rely on this code for anything you
  cannot afford to lose when that happens.
- Pairing requires an SDK token issued for your own account. Keep
  tokens and pairing state files private; they are credentials.

## Related projects

- [musegadget-java](https://github.com/tsuzu/musegadget-java) — the same
  client implemented in pure Java (JDK only, no external dependencies).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

This project is a clean reimplementation informed by the upstream
Apache-2.0-licensed SDK; the pairing test vector JSON is factual test
data reproduced from that SDK.
