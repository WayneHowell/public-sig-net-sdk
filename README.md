# Sig-Net SDK

A C++ library for the **Sig-Net Protocol Framework v0.16** — a secure, CoAP-based DMX512 control protocol for entertainment lighting networks.

The library is designed to compile under general Windows compilers. The test applications are specifically C++Builder.
To just use the binaries, go to \sig-net-example-tid-level-tx\Win32\Debug

[![Platform](https://img.shields.io/badge/platform-Windows-blue)](https://www.embarcadero.com/products/cbuilder)
[![Compiler](https://img.shields.io/badge/compiler-BCC32%20(C%2B%2BBuilder%2011.1)-orange)](https://www.embarcadero.com/products/cbuilder)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-Sig--Net%20v0.12-purple)](https://singularity.co.uk)

## Features

- **CoAP Packet Construction** — RFC 7252 with extended delta encoding
- **HMAC-SHA256 Authentication** — RFC 2104 via Windows BCrypt (zero external dependencies)
- **HKDF Key Derivation** — RFC 5869, derives Sender / Node / Manager keys from shared K0
- **PBKDF2 Passphrase Support** — Derive K0 from a human-memorable passphrase (100 000 iterations)
- **TLV Payload Encoding** — DMX Level, Priority, and Sync messages
- **Multicast Address Calculation** — Universe folding across 100 IPs (239.254.0.1–100)
- **Sequence & Session Management** — Auto-increment with session rollover
- **UDP Multicast Transmission** — Native Winsock2, TTL 16, loopback-enabled
- **Packet Parsing & Validation** — Full Section 8.6 receiver support with anti-replay protection
- **Self-Test Framework** — Embedded test suite covering all major subsystems
- **Reusable VCL Components** — K0 entry dialog and self-test results dialog
- **Zero External Dependencies** — Windows BCrypt and Winsock2 only

## Revisions

### V0.5 – 2026-04-11

Updated to match v0.16 Sig-Net specification.

### V0.4 – 2026-04-09

Added first draft of Node project.

### V0.3 – 2026-04-02

Added C++Builder v10 project files.

Disabled transmit DMX group until K0 set.

Changed all key display to lowercase per v0.14 document

Updated for v0.15 document.

Allowed "from IP" to be loopback for testing.

Added option to send bad frames.

Added test Passcode and K0 buttons:
- Passphrase: `Ge2p$E$4*A`
- `K0`: `52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173`
- Results:
  - `Ks`: `78981fe02576b2e9e47d916853d5967f34f8ae8aaae46db0495b178a75620e89`
  - `Kc`: `1973cecb72f2506f8b5c442c565f0c6a68aee8a873b8ef26e957b88a7fc54b80`
  - `Km_global`: `2f6b76ffe666dc65504be86828277ec9ef8a04fe329652c233ab537ad434fa0d`

### V0.2 – 2026-04-01

Sender URI was set to Endpoint = 0 which is illegal. Corrected.

### V0.1 – 2026-03-31

First release of the "sig-net-example-tid-level-tx.exe"

## Protocol Overview

Sig-Net is a security-first protocol for entertainment lighting control.

- **Cryptographic Authentication** — HMAC-SHA256 on every packet; unauthenticated control is rejected
- **Hierarchical Key Derivation** — HKDF generates Sender, Node, and Manager keys from a shared 256-bit root key (K0); K0 is never transmitted
- **Real-Time Performance** — Designed for 44 Hz sustained control with 1 Hz keep-alive
- **Scalable Multicast** — Up to 63 999 universes folded across 100 multicast groups (239.254.0.1–239.254.0.100)
- **Anti-Replay Protection** — Every packet carries a monotonic Session ID and Sequence Number; receivers enforce strict ordering

## Repository Structure

```
sig-net.hpp                    Master include — add this to your project
sig-net-constants.hpp          Protocol constants, CoAP option numbers, TIDs, error codes
sig-net-types.hpp              Data structures: CoAP header, TLV, PacketBuffer, receiver state
sig-net-crypto.hpp/cpp         HMAC-SHA256, HKDF-Expand, PBKDF2, key derivation
sig-net-coap.hpp/cpp           CoAP header and delta-encoded option building
sig-net-security.hpp/cpp       Sig-Net custom CoAP options and HMAC signing
sig-net-tlv.hpp/cpp            TLV payload encoding (TID_LEVEL, TID_PRIORITY, TID_SYNC)
sig-net-send.hpp/cpp           High-level DMX packet assembly and multicast send
sig-net-parse.hpp/cpp          Packet parsing & Section 8.6 receiver validation
sig-net-selftest.hpp/cpp       Embedded self-test suite (crypto, CoAP, TLV, security, send)

sig-net-example-tid-level-tx/  Transmitter VCL example application
    MainForm.h/cpp/dfm         GUI: K0 entry, DMX test patterns, hex dump, auto-send

sig-net-passcode/              Reusable VCL K0 entry dialog component
    K0EntryDialog.h/cpp/dfm    Supports raw hex entry and passphrase derivation

sig-net-self-test-dialog/      Reusable VCL self-test results dialog component
    SelfTestResultsForm.h/cpp/dfm  Colour-coded pass/fail grid with clipboard export

Docs/
    RECEIVER_IMPLEMENTATION.md Receiver integration reference
```

## Requirements

| Requirement   | Detail                                                        |
|---------------|---------------------------------------------------------------|
| IDE           | C++Builder 11.1 or later                                      |
| Compiler      | BCC32 (Win32 target)                                          |
| Platform      | Windows (Vista or later)                                      |
| Libraries     | `bcrypt.lib`, `ws2_32.lib` — both included in the Windows SDK |
| External deps | **None**                                                      |

## Building the Example Application

1. Open `sig-net-example-tid-level-tx/sig-net-example-tid-level-tx.cbproj` in C++Builder.
2. Select **Build** (Debug or Release). All library `.cpp` files are included via relative paths.
3. The project links `bcrypt.lib` and `ws2_32.lib` automatically.

To embed the library in your own project, add all `sig-net-*.cpp` files and include `sig-net.hpp`.

## Quick Start

```cpp
#include "sig-net.hpp"
using namespace SigNet;

// 1. Set your 32-byte K0 root key
uint8_t k0[32] = { /* provisioned key */ };

// 2. Derive the sender key
uint8_t sender_key[32];
if (Crypto::DeriveSenderKey(k0, sender_key) != SIGNET_SUCCESS) { /* handle error */ }

// 3. Build a DMX Level packet
uint8_t  dmx_data[512] = { /* slot values 0-255 */ };
uint8_t  tuid[6]        = { 0xff, 0xff, 0x00, 0x00, 0x00, 0x01 };
uint32_t session_id     = 1;   // persist across reboots
uint32_t seq_num        = 1;   // auto-incremented each send

PacketBuffer buffer;
int32_t result = BuildDMXPacket(
    buffer,
    517,          // universe
    dmx_data,
    512,          // slot count
    tuid,
    0,            // endpoint
    0x0000,       // manufacturer code (0 = standard)
    session_id,
    seq_num,
    sender_key,
    1             // CoAP message ID
);

// 4. Send via UDP multicast
char multicast_ip[16];
CalculateMulticastAddress(517, multicast_ip);
// → "239.254.0.18"  (formula: ((universe-1) % 100) + 1)

SendMulticast(buffer, multicast_ip, SIGNET_UDP_PORT);

// 5. Advance sequence for next packet
seq_num = IncrementSequence(seq_num);
if (ShouldIncrementSession(seq_num)) {
    session_id++;   // persist new session_id to NVM
    seq_num = 1;
}
```

## K0 Key Entry Format

The spec (v0.12 §7.2.3) defines two entry methods. **Manual hex entry is prohibited** — humans must always use a passphrase.

### Passphrase Entry (Human Interface)

K0 is derived from a UTF-8 passphrase using PBKDF2-HMAC-SHA256:

| Parameter  | Value                                  |
|------------|----------------------------------------|
| Algorithm  | PBKDF2-HMAC-SHA256                     |
| Iterations | 100,000                                |
| Salt       | `Sig-Net-K0-Salt-v1` (18 bytes, ASCII) |
| Output     | 32 bytes (256-bit K0)                  |

Passphrase complexity requirements (enforced by Manager, recommended on Node/Sender):
- Minimum 10 characters, maximum 64 characters
- Characters from at least 3 of: uppercase, lowercase, digits, symbols
- No more than 2 consecutive identical characters
- No more than 3 consecutive sequential characters

### Machine Transfer (Out-of-Band Interface)

For electronic transfer (USB, NFC), K0 is encoded as a plain **64-character uppercase hex string** with no checksum appended:

```
A7B3C8D2E1F45926384A5B6C7D8E9F0121324354657687980A1B2C3D4E5F6071
└──────────────────── 32 bytes (64 hex chars) ──────────────────────┘
```

JSON format for file-based transfer:
```json
{ "sig-net_k0": "A7B3C8D2E1F45926384A5B6C7D8E9F0121324354657687980A1B2C3D4E5F6071" }
```

## Multicast Address Mapping

Universe numbers are folded into 100 multicast groups using `((universe - 1) % 100) + 1`:

| Universe | Multicast IP |
|----------|-------------|
| 1 | 239.254.0.1 |
| 100 | 239.254.0.100 |
| 101 | 239.254.0.1 (same as universe 1) |
| 517 | 239.254.0.18 |

Receivers join the multicast group corresponding to the universe they wish to receive; all senders for that group share the address. HMAC authentication prevents cross-universe spoofing.

## Error Codes

| Code | Constant                   | Description                     |
|------|----------------------------|---------------------------------|
| 0    | `SIGNET_SUCCESS`           | Operation successful            |
| -1   | `SIGNET_ERROR_INVALID_ARG` | Invalid argument                |
| -2   | `SIGNET_ERROR_BUFFER_FULL` | Packet exceeds MTU (1400 bytes) |
| -3   | `SIGNET_ERROR_CRYPTO`      | Cryptographic operation failed  |
| -4   | `SIGNET_ERROR_ENCODE`      | Encoding error                  |
| -5   | `SIGNET_ERROR_NETWORK`     | Network transmission failed     |

## Security Considerations

- **K0 is never transmitted.** Only derived keys (Sender Key, Node Key, Manager Key) are used on the wire.
- **Session ID must be stored in non-volatile memory** and incremented on every reboot before transmitting. Receivers reject packets from sessions they have already seen.
- **Sequence numbers are strictly monotonic** within a session. Receivers reject out-of-order or replayed packets.
- **HMAC covers the full packet** including all CoAP options; any modification is detected and the packet is discarded.

## Self-Test Framework

The library includes an embedded self-test suite for integration verification:

```cpp
#include "sig-net-selftest.hpp"
using namespace SigNet;

TestSuiteResults results = RunAllTests();
// results contains pass/fail status for every sub-test

// Or display in the VCL dialog:
#include "SelfTestResultsForm.h"
TSelfTestResultsForm* form = new TSelfTestResultsForm(Application);
form->ShowModal();
delete form;
```

## Protocol Specifications

| Attribute | Value |
|-----------|-------|
| Sig-Net version | v0.12 |
| Base protocol | CoAP (RFC 7252) |
| Authentication | HMAC-SHA256 (RFC 2104) |
| Key derivation | HKDF-Expand (RFC 5869 §2.3) |
| Passphrase KDF | PBKDF2-HMAC-SHA256, 100 000 iterations |
| Transport | UDP Multicast, port 5683 |
| Maximum packet size | 1400 bytes |
| Maximum TX rate | 44 Hz (active), 1 Hz (keep-alive) |

## License

Copyright © 2026 Singularity (UK) Ltd.

Released under the [MIT License](LICENSE). See source file headers for full terms.

## Author

Wayne Howell — Singularity (UK) Ltd.
